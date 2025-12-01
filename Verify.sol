// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title CredentialVerifier
 * @notice Cross-chain credential verification contract
 * @dev Verifies credentials anchored on origin chain using zkBridge proofs
 */
contract CredentialVerifier {
    
    // Verification result structure
    struct VerificationResult {
        bool verified;
        uint256 verifiedAt;
        bytes32 credentialHash;
        address originChainAnchor;
        uint256 originChainId;
    }
    
    // Constants
    uint256 public constant MAX_BATCH_SIZE = 50;
    
    // Storage
    mapping(bytes32 => VerificationResult) public verifications; // key: keccak256(credentialHash, originChainId)
    mapping(address => bool) public trustedVerifiers; // Backend/relayer addresses
    mapping(address => uint256) public verifierRemovalTime; // verifier => earliest removal timestamp
    address public owner;
    address public pendingOwner; // For 2-step ownership transfer
    
    // Constants
    uint256 public constant VERIFIER_REMOVAL_DELAY = 1 days;
    
    // MVP mode settings
    bool public mvpMode;
    uint256 public mvpModeExpiry; // Timestamp when MVP mode must be disabled
    
    // Pausable state
    bool public paused;
    
    // Events
    event CredentialVerified(
        bytes32 indexed credentialHash,
        address indexed verifier,
        uint256 originChainId,
        address originChainAnchor,
        uint256 timestamp
    );
    
    event VerifierAdded(address indexed verifier);
    event VerifierRemoved(address indexed verifier);
    event MvpModeDisabled(uint256 timestamp);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event Paused(address account);
    event Unpaused(address account);
    
    // Errors
    error Unauthorized();
    error AlreadyVerified();
    error InvalidProof();
    error InvalidCredentialHash();
    error InvalidOriginChain();
    error InvalidAnchorAddress();
    error BatchSizeExceeded();
    error MvpModeExpired();
    error ProofValidationNotImplemented();
    error EnforcedPause();
    error ExpectedPause();
    
    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }
    
    modifier onlyTrustedVerifier() {
        if (!trustedVerifiers[msg.sender] && msg.sender != owner) revert Unauthorized();
        _;
    }
    
    modifier whenNotPaused() {
        if (paused) revert EnforcedPause();
        _;
    }
    
    modifier whenPaused() {
        if (!paused) revert ExpectedPause();
        _;
    }
    
    /**
     * @notice Constructor
     * @param _mvpModeDuration Duration in seconds for MVP mode (e.g., 90 days = 7776000)
     */
    constructor(uint256 _mvpModeDuration) {
        owner = msg.sender;
        trustedVerifiers[msg.sender] = true;
        mvpMode = true;
        mvpModeExpiry = block.timestamp + _mvpModeDuration;
        paused = false;
    }
    
    /**
     * @notice Verify a credential from origin chain
     * @param credentialHash Hash of the credential
     * @param originChainId Chain ID where credential was issued
     * @param originChainAnchor Address of anchor contract on origin chain
     * @param proof zkBridge proof (placeholder for MVP - can be empty)
     */
    function verifyCredential(
        bytes32 credentialHash,
        uint256 originChainId,
        address originChainAnchor,
        bytes calldata proof
    ) external onlyTrustedVerifier whenNotPaused {
        // Validate inputs
        if (credentialHash == bytes32(0)) revert InvalidCredentialHash();
        if (originChainId == 0) revert InvalidOriginChain();
        if (originChainAnchor == address(0)) revert InvalidAnchorAddress();
        
        // Use composite key to prevent cross-chain replay attacks
        bytes32 verificationKey = _getVerificationKey(credentialHash, originChainId);
        
        if (verifications[verificationKey].verified) revert AlreadyVerified();
        
        // Validate proof
        _validateProof(proof);
        
        verifications[verificationKey] = VerificationResult({
            verified: true,
            verifiedAt: block.timestamp,
            credentialHash: credentialHash,
            originChainAnchor: originChainAnchor,
            originChainId: originChainId
        });
        
        emit CredentialVerified(
            credentialHash,
            msg.sender,
            originChainId,
            originChainAnchor,
            block.timestamp
        );
    }
    
    /**
     * @notice Check if credential is verified on a specific chain
     * @param credentialHash Hash to check
     * @param originChainId Chain ID to check
     * @return verified True if credential has been verified
     */
    function isVerified(bytes32 credentialHash, uint256 originChainId) external view returns (bool) {
        bytes32 verificationKey = _getVerificationKey(credentialHash, originChainId);
        return verifications[verificationKey].verified;
    }
    
    /**
     * @notice Get verification details for a specific chain
     * @param credentialHash Hash to check
     * @param originChainId Chain ID to check
     */
    function getVerification(bytes32 credentialHash, uint256 originChainId)
        external
        view
        returns (
            bool verified,
            uint256 verifiedAt,
            address originChainAnchor,
            uint256 _originChainId
        )
    {
        bytes32 verificationKey = _getVerificationKey(credentialHash, originChainId);
        VerificationResult memory result = verifications[verificationKey];
        return (
            result.verified,
            result.verifiedAt,
            result.originChainAnchor,
            result.originChainId
        );
    }
    
    /**
     * @notice Add trusted verifier (backend/relayer)
     */
    function addVerifier(address verifier) external onlyOwner {
        trustedVerifiers[verifier] = true;
        emit VerifierAdded(verifier);
    }
    
    /**
     * @notice Schedule removal of a trusted verifier (requires delay)
     * @param verifier Address to schedule for removal
     */
    function scheduleVerifierRemoval(address verifier) external onlyOwner {
        verifierRemovalTime[verifier] = block.timestamp + VERIFIER_REMOVAL_DELAY;
    }
    
    /**
     * @notice Remove trusted verifier (after delay)
     * @param verifier Address to remove
     */
    function removeVerifier(address verifier) external onlyOwner {
        require(
            verifierRemovalTime[verifier] > 0 && block.timestamp >= verifierRemovalTime[verifier],
            "Removal not ready"
        );
        trustedVerifiers[verifier] = false;
        verifierRemovalTime[verifier] = 0;
        emit VerifierRemoved(verifier);
    }
    
    /**
     * @notice Disable MVP mode (transition to production mode)
     * @dev Once disabled, cannot be re-enabled
     */
    function disableMvpMode() external onlyOwner {
        mvpMode = false;
        emit MvpModeDisabled(block.timestamp);
    }
    
    /**
     * @notice Pause all verification operations
     * @dev Can be used in emergencies to stop all verifications
     */
    function pause() external onlyOwner {
        paused = true;
        emit Paused(msg.sender);
    }
    
    /**
     * @notice Unpause verification operations
     */
    function unpause() external onlyOwner whenPaused {
        paused = false;
        emit Unpaused(msg.sender);
    }
    
    /**
     * @notice Starts the 2-step ownership transfer process
     * @param newOwner Address of the new owner
     */
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert Unauthorized();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }
    
    /**
     * @notice Accepts the ownership transfer
     * @dev Can only be called by the pending owner
     */
    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert Unauthorized();
        address oldOwner = owner;
        owner = pendingOwner;
        pendingOwner = address(0);
        emit OwnershipTransferred(oldOwner, owner);
    }
    
    /**
     * @notice Validate  proof
     * @dev MVP mode accepts proofs with expiry check. Production requires actual  verification
     */
    function _validateProof(bytes calldata proof) internal view {
        if (mvpMode) {
            // In MVP mode, check expiry
            if (block.timestamp > mvpModeExpiry) revert MvpModeExpired();
            // Require at least non-empty proof
            if (proof.length == 0) revert InvalidProof();
            // Trust the verifier for now
            return;
        }
        
        // Production mode requires actual validation
        revert ProofValidationNotImplemented();
    }
    
    /**
     * @notice Batch verify multiple credentials
     * @return verifiedCount Number of credentials actually verified (skips already verified)
     */
    function batchVerifyCredentials(
        bytes32[] calldata credentialHashes,
        uint256[] calldata originChainIds,
        address[] calldata originChainAnchors,
        bytes[] calldata proofs
    ) external onlyTrustedVerifier whenNotPaused returns (uint256 verifiedCount) {
        // Validate array lengths
        if (credentialHashes.length == 0) revert InvalidCredentialHash();
        if (credentialHashes.length > MAX_BATCH_SIZE) revert BatchSizeExceeded();
        
        require(
            credentialHashes.length == originChainIds.length &&
            credentialHashes.length == originChainAnchors.length &&
            credentialHashes.length == proofs.length,
            "Array length mismatch"
        );
        
        // Validate ALL inputs first to prevent gas bombs
        for (uint256 i = 0; i < credentialHashes.length; i++) {
            if (credentialHashes[i] == bytes32(0)) revert InvalidCredentialHash();
            if (originChainIds[i] == 0) revert InvalidOriginChain();
            if (originChainAnchors[i] == address(0)) revert InvalidAnchorAddress();
        }
        
        verifiedCount = 0;
        
        // Process verifications
        for (uint256 i = 0; i < credentialHashes.length; i++) {
            bytes32 verificationKey = _getVerificationKey(credentialHashes[i], originChainIds[i]);
            
            // Skip if already verified
            if (verifications[verificationKey].verified) continue;
            
            _validateProof(proofs[i]);
            
            verifications[verificationKey] = VerificationResult({
                verified: true,
                verifiedAt: block.timestamp,
                credentialHash: credentialHashes[i],
                originChainAnchor: originChainAnchors[i],
                originChainId: originChainIds[i]
            });
            
            emit CredentialVerified(
                credentialHashes[i],
                msg.sender,
                originChainIds[i],
                originChainAnchors[i],
                block.timestamp
            );
            
            verifiedCount++;
        }
        
        return verifiedCount;
    }
    
    /**
     * @notice Get composite verification key to prevent cross-chain replays
     * @param credentialHash The credential hash
     * @param originChainId The origin chain ID
     * @return key The composite key
     */
    function _getVerificationKey(bytes32 credentialHash, uint256 originChainId) 
        internal 
        pure 
        returns (bytes32) 
    {
        return keccak256(abi.encodePacked(credentialHash, originChainId));
    }
}
