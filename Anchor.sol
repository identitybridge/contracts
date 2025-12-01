// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title CredentialAnchor
 * @notice Privacy-preserving credential commitment registry
 * @dev Stores only hashes of credentials, never PII
 */
contract CredentialAnchor {
    
    // Credential commitment structure
    struct CredentialCommit {
        bool published;
        bool revoked;
        address issuer;
        uint256 publishedAt;
        uint256 revokedAt;
        uint256 expiry; // Optional: 0 means no expiry
        bytes32 zkVerifyAttestationId; // Optional: zkVerify attestation ID (0x0 if not set)
    }
    
    // Constants
    uint256 public constant UPDATE_GRACE_PERIOD = 7 days; // Minimum time before update/rotation
    
    // Storage
    mapping(bytes32 => CredentialCommit) public commits;
    
    // Events
    event CommitPublished(
        bytes32 indexed credentialHash,
        address indexed issuer,
        uint256 timestamp,
        uint256 expiry
    );
    
    event CommitRevoked(
        bytes32 indexed credentialHash,
        address indexed revoker,
        uint256 timestamp
    );
    
    event CommitUpdated(
        bytes32 indexed oldHash,
        bytes32 indexed newHash,
        uint256 timestamp
    );
    
    event ZkVerifyAttestationSet(
        bytes32 indexed credentialHash,
        bytes32 indexed attestationId,
        uint256 timestamp
    );
    
    // Errors
    error AlreadyPublished();
    error NotPublished();
    error AlreadyRevoked();
    error Expired();
    error Unauthorized();
    error InvalidCredentialHash();
    error InvalidExpiry();
    error InvalidAttestationId();
    error AttestationAlreadySet();
    error UpdateTooSoon();
    
    /**
     * @notice Publish a new credential commitment
     * @param credentialHash Keccak256 hash of the credential
     * @param expiry Expiration timestamp (0 for no expiry)
     */
    function publishCommit(
        bytes32 credentialHash,
        uint256 expiry
    ) external {
        if (credentialHash == bytes32(0)) revert InvalidCredentialHash();
        if (commits[credentialHash].published) revert AlreadyPublished();
        
        // Validate expiry is either 0 (no expiry) or in the future
        if (expiry > 0 && expiry <= block.timestamp) revert InvalidExpiry();
        
        commits[credentialHash] = CredentialCommit({
            published: true,
            revoked: false,
            issuer: msg.sender,
            publishedAt: block.timestamp,
            revokedAt: 0,
            expiry: expiry,
            zkVerifyAttestationId: bytes32(0) // Initialize to 0 (not set)
        });
        
        emit CommitPublished(credentialHash, msg.sender, block.timestamp, expiry);
    }
    
    /**
     * @notice Revoke a credential commitment
     * @param credentialHash Hash of the credential to revoke
     */
    function revokeCommit(bytes32 credentialHash) external {
        CredentialCommit storage commit = commits[credentialHash];
        
        if (!commit.published) revert NotPublished();
        if (commit.revoked) revert AlreadyRevoked();
        if (msg.sender != commit.issuer) revert Unauthorized();
        
        commit.revoked = true;
        commit.revokedAt = block.timestamp;
        
        emit CommitRevoked(credentialHash, msg.sender, block.timestamp);
    }
    
    /**
     * @notice Update/rotate a credential (revoke old, publish new)
     * @param oldHash Hash of old credential
     * @param newHash Hash of new credential
     * @param expiry Expiry for new credential
     */
    function updateCommit(
        bytes32 oldHash,
        bytes32 newHash,
        uint256 expiry
    ) external {
        // Validate input hashes
        if (oldHash == bytes32(0) || newHash == bytes32(0)) revert InvalidCredentialHash();
        
        CredentialCommit storage oldCommit = commits[oldHash];
        
        if (!oldCommit.published) revert NotPublished();
        if (oldCommit.revoked) revert AlreadyRevoked();
        if (msg.sender != oldCommit.issuer) revert Unauthorized();
        if (commits[newHash].published) revert AlreadyPublished();
        
        // Enforce grace period to protect holders
        if (block.timestamp < oldCommit.publishedAt + UPDATE_GRACE_PERIOD) revert UpdateTooSoon();
        
        // Validate expiry is either 0 (no expiry) or in the future
        if (expiry > 0 && expiry <= block.timestamp) revert InvalidExpiry();
        
        // Revoke old
        oldCommit.revoked = true;
        oldCommit.revokedAt = block.timestamp;
        
        // Publish new
        commits[newHash] = CredentialCommit({
            published: true,
            revoked: false,
            issuer: msg.sender,
            publishedAt: block.timestamp,
            revokedAt: 0,
            expiry: expiry,
            zkVerifyAttestationId: bytes32(0) // Initialize to 0 (not set)
        });
        
        emit CommitRevoked(oldHash, msg.sender, block.timestamp);
        emit CommitUpdated(oldHash, newHash, block.timestamp);
    }
    
    /**
     * @notice Check if credential is currently valid
     * @param credentialHash Hash to check
     * @return valid True if published, not revoked, and not expired
     */
    function isValid(bytes32 credentialHash) external view returns (bool valid) {
        CredentialCommit memory commit = commits[credentialHash];
        
        if (!commit.published) return false;
        if (commit.revoked) return false;
        if (commit.expiry > 0 && block.timestamp > commit.expiry) return false;
        
        return true;
    }
    
    /**
     * @notice Check if credential is published
     */
    function isPublished(bytes32 credentialHash) external view returns (bool) {
        return commits[credentialHash].published;
    }
    
    /**
     * @notice Check if credential is revoked
     */
    function isRevoked(bytes32 credentialHash) external view returns (bool) {
        return commits[credentialHash].revoked;
    }
    
    /**
     * @notice Set zkVerify attestation ID for a credential
     * @param credentialHash Hash of the credential
     * @param attestationId zkVerify attestation ID
     */
    function setZkVerifyAttestationId(
        bytes32 credentialHash,
        bytes32 attestationId
    ) external {
        CredentialCommit storage commit = commits[credentialHash];
        
        if (!commit.published) revert NotPublished();
        if (msg.sender != commit.issuer) revert Unauthorized();
        if (attestationId == bytes32(0)) revert InvalidAttestationId();
        if (commit.zkVerifyAttestationId != bytes32(0)) revert AttestationAlreadySet();
        
        commit.zkVerifyAttestationId = attestationId;
        
        emit ZkVerifyAttestationSet(credentialHash, attestationId, block.timestamp);
    }
    
    /**
     * @notice Get zkVerify attestation ID for a credential
     * @param credentialHash Hash of the credential
     * @return attestationId The zkVerify attestation ID (0x0 if not set)
     */
    function getZkVerifyAttestationId(bytes32 credentialHash) 
        external 
        view 
        returns (bytes32 attestationId) 
    {
        return commits[credentialHash].zkVerifyAttestationId;
    }
    
    /**
     * @notice Get full credential commitment details
     */
    function getCommit(bytes32 credentialHash) 
        external 
        view 
        returns (
            bool published,
            bool revoked,
            address issuer,
            uint256 publishedAt,
            uint256 revokedAt,
            uint256 expiry,
            bytes32 zkVerifyAttestationId
        ) 
    {
        CredentialCommit memory commit = commits[credentialHash];
        return (
            commit.published,
            commit.revoked,
            commit.issuer,
            commit.publishedAt,
            commit.revokedAt,
            commit.expiry,
            commit.zkVerifyAttestationId
        );
    }
}
