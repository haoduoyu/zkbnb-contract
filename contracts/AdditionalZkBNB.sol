// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/math/SafeCast.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "./lib/Utils.sol";

import "./Storage.sol";
import "./Config.sol";
import "./interfaces/Events.sol";

import "./lib/Bytes.sol";
import "./lib/TxTypes.sol";

import "./ExodusVerifier.sol";

/// @title ZkBNB additional main contract
/// @author ZkBNB
contract AdditionalZkBNB is Storage, Config, Events {
  function increaseBalanceToWithdraw(bytes22 _packedBalanceKey, uint128 _amount) internal {
    uint128 balance = pendingBalances[_packedBalanceKey].balanceToWithdraw;
    pendingBalances[_packedBalanceKey] = PendingBalance(balance + _amount, FILLED_GAS_RESERVE_VALUE);
  }

  /*
        StateRoot
            AccountRoot
            NftRoot
        Account
            AccountIndex
            AccountNameHash bytes32
            PublicKey
            AssetRoot
        Asset
           AssetId
           Balance
        Nft
    */
  function performDesert(
    /* StoredBlockInfo memory _storedBlockInfo, */
    bytes32 _nftRoot,
    ExodusVerifier.ExitData calldata _exitData,
    bytes32[16] calldata _assetMerkleProof,
    bytes32[32] calldata _accountMerkleProof
  ) external {
    require(_exitData.accountId <= MAX_ACCOUNT_INDEX, "e");
    require(_exitData.accountId != SPECIAL_ACCOUNT_ID, "v");

    // must be in exodus mode
    require(desertMode, "s");
    // already exited
    require(!performedDesert[_exitData.accountId][_exitData.assetId], "t");

    /* require(storedBlockHashes[totalBlocksVerified] == hashStoredBlockInfo(_storedBlockInfo), "u"); */
    // incorrect stored block info

    bool proofCorrect = exodusVerifier.verifyExitProofBalance(
      uint256(stateRoot),
      uint256(_nftRoot),
      _exitData,
      _assetMerkleProof,
      _accountMerkleProof
    );
    require(proofCorrect, "x");

    address owner = znsController.getOwner(_exitData.accountNameHash);
    require(owner == msg.sender, "z");

    performedDesert[_exitData.accountId][_exitData.assetId] = true;
  }

  /// @notice perform desert mode for nft
  function performDesertNft(
    uint _ownerAccountIndex,
    bytes32 _accountRoot,
    ExodusVerifier.ExitNftData[] memory _exitNfts,
    bytes32[40][] memory _nftMerkleProofs
  ) external {
    require(_ownerAccountIndex <= MAX_ACCOUNT_INDEX, "e");
    require(_ownerAccountIndex != SPECIAL_ACCOUNT_ID, "v");

    require(_exitNfts.length >= 1, "Z");

    bool proofCorrect = exodusVerifier.verifyExitNftProof(
      uint256(stateRoot),
      uint256(_accountRoot),
      _ownerAccountIndex,
      _exitNfts,
      _nftMerkleProofs
    );
    require(proofCorrect, "x");

    /* TxTypes.WithdrawNFT memory withdrawNftOp = TxTypes.WithdrawNFT({ */
    /*   txType: uint8(TxTypes.TxType.WithdrawNFT), */
    /*   accountIndex: _exitData.creatorAccountIndex, */
    /*   toAddress: _nftCreatorAddress, */
    /*   proxyAddress: _nftCreatorAddress, */
    /*   nftAssetId: _nftSerialId, */
    /*   gasFeeAccountIndex: 0, */
    /*   gasFeeAssetId: 0, */
    /*   gasFeeAssetAmount: 0 */
    /* }); */
    /* pendingWithdrawnNFTs[_tokenId] = withdrawNftOp; */
    /* emit WithdrawalNFTPending(_tokenId); */

    /* performedDesertNft[_exitData.accountId][_exitData.assetId] = true; */
  }

  function cancelOutstandingDepositsForExodusMode(uint64 _n, bytes[] memory _depositsPubData) external {
    require(desertMode, "8");
    // exodus mode not active
    uint64 toProcess = Utils.minU64(totalOpenPriorityRequests, _n);
    require(toProcess > 0, "9");
    // no deposits to process
    uint64 currentDepositIdx = 0;
    for (uint64 id = firstPriorityRequestId; id < firstPriorityRequestId + toProcess; id++) {
      if (priorityRequests[id].txType == TxTypes.TxType.Deposit) {
        bytes memory depositPubdata = _depositsPubData[currentDepositIdx];
        require(Utils.hashBytesToBytes20(depositPubdata) == priorityRequests[id].hashedPubData, "a");
        ++currentDepositIdx;

        TxTypes.Deposit memory _tx = TxTypes.readDepositPubData(depositPubdata);
        address owner = znsController.getOwner(_tx.accountNameHash);
        bytes22 packedBalanceKey = packAddressAndAssetId(owner, uint16(_tx.assetId));
        pendingBalances[packedBalanceKey].balanceToWithdraw += _tx.amount;
      }
      delete priorityRequests[id];
    }
    firstPriorityRequestId += toProcess;
    totalOpenPriorityRequests -= toProcess;
  }

  /// @notice Reverts unverified blocks
  function revertBlocks(StoredBlockInfo[] memory _blocksToRevert) external onlyActive {
    governance.isActiveValidator(msg.sender);

    uint32 blocksCommitted = totalBlocksCommitted;
    uint32 blocksToRevert = Utils.minU32(uint32(_blocksToRevert.length), blocksCommitted - totalBlocksVerified);
    uint64 revertedPriorityRequests = 0;

    for (uint32 i = 0; i < blocksToRevert; ++i) {
      StoredBlockInfo memory storedBlockInfo = _blocksToRevert[i];
      require(storedBlockHashes[blocksCommitted] == hashStoredBlockInfo(storedBlockInfo), "r");
      // incorrect stored block info

      delete storedBlockHashes[blocksCommitted];

      --blocksCommitted;
      revertedPriorityRequests += storedBlockInfo.priorityOperations;
    }

    totalBlocksCommitted = blocksCommitted;
    totalCommittedPriorityRequests -= revertedPriorityRequests;
    if (totalBlocksCommitted < totalBlocksVerified) {
      totalBlocksVerified = totalBlocksCommitted;
    }

    emit BlocksRevert(totalBlocksVerified, blocksCommitted);
  }

  function registerZNS(
    string calldata _name,
    address _owner,
    bytes32 _zkbnbPubKeyX,
    bytes32 _zkbnbPubKeyY
  ) external payable {
    // Register ZNS
    (bytes32 node, uint32 accountIndex) = znsController.registerZNS{value: msg.value}(
      _name,
      _owner,
      _zkbnbPubKeyX,
      _zkbnbPubKeyY,
      address(znsResolver)
    );

    // Priority Queue request
    TxTypes.RegisterZNS memory _tx = TxTypes.RegisterZNS({
      txType: uint8(TxTypes.TxType.RegisterZNS),
      accountIndex: accountIndex,
      accountName: Utils.stringToBytes20(_name),
      accountNameHash: node,
      pubKeyX: _zkbnbPubKeyX,
      pubKeyY: _zkbnbPubKeyY
    });
    // compact pub data
    bytes memory pubData = TxTypes.writeRegisterZNSPubDataForPriorityQueue(_tx);

    // add into priority request queue
    addPriorityRequest(TxTypes.TxType.RegisterZNS, pubData);

    emit RegisterZNS(_name, node, _owner, _zkbnbPubKeyX, _zkbnbPubKeyY, accountIndex);
  }

  /// @notice Deposit Native Assets to Layer 2 - transfer ether from user into contract, validate it, register deposit
  /// @param _accountName the receiver account name
  function depositBNB(string calldata _accountName) external payable onlyActive {
    require(msg.value != 0, "ia");
    bytes32 accountNameHash = znsController.getSubnodeNameHash(_accountName);
    require(znsController.isRegisteredNameHash(accountNameHash), "nr");
    registerDeposit(0, SafeCast.toUint128(msg.value), accountNameHash);
  }

  /// @notice Deposit or Lock BEP20 token to Layer 2 - transfer ERC20 tokens from user into contract, validate it, register deposit
  /// @param _token Token address
  /// @param _amount Token amount
  /// @param _accountName Receiver Layer 2 account name
  function depositBEP20(IERC20 _token, uint104 _amount, string calldata _accountName) external onlyActive {
    require(_amount != 0, "I");
    bytes32 accountNameHash = znsController.getSubnodeNameHash(_accountName);
    require(znsController.isRegisteredNameHash(accountNameHash), "N");
    // Get asset id by its address
    uint16 assetId = governance.validateAssetAddress(address(_token));
    require(!governance.pausedAssets(assetId), "b");
    // token deposits are paused

    uint256 balanceBefore = _token.balanceOf(address(this));
    require(Utils.transferFromERC20(_token, msg.sender, address(this), SafeCast.toUint128(_amount)), "c");
    // token transfer failed deposit
    uint256 balanceAfter = _token.balanceOf(address(this));
    uint128 depositAmount = SafeCast.toUint128(balanceAfter - balanceBefore);
    require(depositAmount <= MAX_DEPOSIT_AMOUNT, "C");
    require(depositAmount > 0, "D");

    registerDeposit(assetId, depositAmount, accountNameHash);
  }

  /// @notice Register deposit request - pack pubdata, add into onchainOpsCheck and emit OnchainDeposit event
  /// @param _assetId Asset by id
  /// @param _amount Asset amount
  /// @param _accountNameHash Receiver Account Name
  function registerDeposit(uint16 _assetId, uint128 _amount, bytes32 _accountNameHash) internal {
    // Priority Queue request
    TxTypes.Deposit memory _tx = TxTypes.Deposit({
      txType: uint8(TxTypes.TxType.Deposit),
      accountIndex: 0, // unknown at the moment
      accountNameHash: _accountNameHash,
      assetId: _assetId,
      amount: _amount
    });
    // compact pub data
    bytes memory pubData = TxTypes.writeDepositPubDataForPriorityQueue(_tx);
    // add into priority request queue
    addPriorityRequest(TxTypes.TxType.Deposit, pubData);
    emit Deposit(_assetId, _accountNameHash, _amount);
  }

  /// @notice Saves priority request in storage
  /// @dev Calculates expiration block for request, store this request and emit NewPriorityRequest event
  /// @param _txType Rollup _tx type
  /// @param _pubData _tx pub data
  function addPriorityRequest(TxTypes.TxType _txType, bytes memory _pubData) internal {
    // Expiration block is: current block number + priority expiration delta
    uint64 expirationBlock = uint64(block.number + PRIORITY_EXPIRATION);

    uint64 nextPriorityRequestId = firstPriorityRequestId + totalOpenPriorityRequests;

    bytes20 hashedPubData = Utils.hashBytesToBytes20(_pubData);

    priorityRequests[nextPriorityRequestId] = PriorityTx({
      hashedPubData: hashedPubData,
      expirationBlock: expirationBlock,
      txType: _txType
    });

    emit NewPriorityRequest(msg.sender, nextPriorityRequestId, _txType, _pubData, uint256(expirationBlock));

    totalOpenPriorityRequests++;
  }
}
