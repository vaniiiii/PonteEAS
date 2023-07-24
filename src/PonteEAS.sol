//SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "@semaphore-protocol/contracts/interfaces/ISemaphore.sol";
import "@semaphore-protocol/contracts/interfaces/ISemaphoreVerifier.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "./ISchemaRegistry.sol";
import "./IEAS.sol";
import "@openzeppelin/contracts/access/Ownable.sol"; // Access control with roles more suitable for further versions

contract Ponte is Ownable {
    struct Group {
        uint256 id;
        bytes32 schema;
        address attester;
        string uri;
    }

    ISemaphore public semaphore;
    ISemaphoreVerifier public verifier;
    ISchemaRegistry public schemaRegister;
    IEAS public eas;

    mapping(address => bool) public attesters;
    mapping(uint256 => uint256) public ids; // semaphore group to groups array id mapping

    Group[] public groups;

    event MessageSent(uint256 message, uint256 groupId);

    constructor(
        address _semaphoreAddress,
        address _verifierAddress,
        address _schemaAddress,
        address _eas
    ) {
        semaphore = ISemaphore(_semaphoreAddress);
        verifier = ISemaphoreVerifier(_verifierAddress);
        schemaRegister = ISchemaRegistry(_schemaAddress);
        eas = IEAS(_eas);
    }

    function createGroup(
        uint256 _groupId,
        bytes32 _schemaId,
        address _attester,
        string calldata _uri
    ) external onlyOwner {
        semaphore.createGroup(_groupId, 20, address(this));
        groups.push(Group(_groupId, _schemaId, _attester, _uri));
        attesters[_attester] = true;
        ids[_groupId] = groups.length - 1; // check this
    }

    function joinGroup(
        uint256 _identityCommitment,
        uint256 _groupId,
        bytes32 _uid
    ) external {
        Attestation memory _attestation = eas.getAttestation(_uid);
        Group memory _group = getGroup(ids[_groupId]);
        //check if schema is good one
        require(_attestation.schema == _group.schema, "Schema is not matching");
        // check if attester is good
        require(
            _attestation.attester == _group.attester,
            "This attestation is not approved by official attester/s"
        );
        // check if msg.sender is recipient
        require(
            _attestation.recipient == msg.sender,
            "You are not owner of this attestation"
        );
        semaphore.addMember(_groupId, _identityCommitment);
    }

    function removeMember(
        bytes32 _uid,
        uint256 _groupId,
        uint256 _identityCommitment,
        uint256[] calldata _proofSiblings,
        uint8[] calldata _proofPathIndices
    ) external {
        Attestation memory _attestation = eas.getAttestation(_uid);
        require(_attestation.revocationTime != 0, "Attestation is not revoked"); // if attestation is revoked, removeMember
        semaphore.removeMember(
            _groupId,
            _identityCommitment,
            _proofSiblings,
            _proofPathIndices
        ); // anyone can do this if attestation is revoked
    }

    function registerNewSchema(
        string calldata _schema,
        address _resolverAddress,
        bool _revocable
    ) external onlyOwner {
        // add modifier potentially
        ISchemaResolver _resolver = ISchemaResolver(_resolverAddress);
        schemaRegister.register(_schema, _resolver, _revocable);
        // add logic to save/map UIDs or any shit?
    }

    function attest(
        AttestationRequest calldata _request
    ) external payable onlyOwner {
        eas.attest(_request);
    }

    function revoke(RevocationRequest calldata _request) external {
        // no need for modifiers, revoke itself is checking who's revoking the attestation
        eas.revoke(_request);
    }

    function sendReview(
        uint256 groupId,
        uint256 review,
        uint256 merkleTreeRoot,
        uint256 nullifierHash,
        uint256[8] calldata proof
    ) external {
        semaphore.verifyProof(
            groupId,
            merkleTreeRoot,
            review,
            nullifierHash,
            groupId,
            proof
        );
    }

    function sendMessage(
        uint256 message,
        uint256 nullifierHash,
        uint256 _groupId,
        uint256 merkleTreeDepth,
        uint256 merkleTreeRoot,
        uint256[8] calldata proof
    ) external {
        // no need for nullifier, directly call verifier
        verifier.verifyProof(
            merkleTreeRoot,
            nullifierHash,
            message,
            _groupId,
            proof,
            merkleTreeDepth
        );
        emit MessageSent(message, _groupId);
    }

    function getGroup(uint _groupId) public view returns (Group memory) {
        return groups[_groupId];
    }
}
