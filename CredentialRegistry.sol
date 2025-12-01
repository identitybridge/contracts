// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./IVerifyProofAggregation.sol";

/**
 * @title CredentialRegistry
 * @notice Registry for associating credential hashes with holder addresses
 * @dev Complements Anchor.sol by providing holder tracking without modifying the core anchor contract
 * Supports ZKP-based claiming to ensure only the intended holder can claim their credential
 * Uses zkVerify's aggregation system for on-chain proof verification
 */
contract CredentialRegistry {
    
    // Registry entry structure
    struct RegistryEntry {
        bytes32 credentialHash;
        address holder;
        address issuer;
        uint256 registeredAt;
        bool active;
    }
    
    // Constants for zkVerify aggregation
    bytes32 public constant PROVING_SYSTEM_ID = keccak256(abi.encodePacked("groth16"));
    bytes32 public constant VERSION_HASH = sha256(abi.encodePacked(""));
    uint256 public constant MAX_BATCH_SIZE = 100;
    uint256 public constant MAX_CREDENTIALS_PER_HOLDER = 1000;
    
    // Storage
    mapping(address => bytes32[]) public holderCredentials; // holder => credential hashes
    mapping(bytes32 => address) public credentialHolder; // credential hash => holder
    mapping(bytes32 => RegistryEntry) public registry; // credential hash => entry
    mapping(address => bool) public trustedRegistrars; // addresses that can register credentials
    address public owner;
    
    // Envelope claiming storage
    mapping(bytes32 => bool) public usedSecretCommitments; // prevent replay attacks
    mapping(bytes32 => bytes32) public commitmentToCredential; // secretCommitment => credentialHash
    
    // Reference to Anchor contract (required for ZKP-based claiming)
    address public anchorContract;
    
    // zkVerify contract for aggregation verification
    IVerifyProofAggregation public zkVerifyContract;
    
    // Verification key hash for the credential ownership circuit
    bytes32 public vkey;
    
    // Verification key hash for the constraint circuit
    bytes32 public constraintVkey;
    
    // Events
    event CredentialRegistered(
        bytes32 indexed credentialHash,
        address indexed holder,
        address indexed issuer,
        uint256 timestamp
    );
    
    event CredentialClaimed(
        bytes32 indexed credentialHash,
        address indexed holder,
        uint256 timestamp
    );
    
    event CredentialClaimedWithDisclosure(
        bytes32 indexed credentialHash,
        address indexed holder,
        uint256 timestamp,
        uint256 disclosureFlags,
        uint256 disclosedCourseName,
        uint256 disclosedInstitution,
        uint256 disclosedCompletionDate,
        uint256 disclosedIssuanceDate,
        uint256 disclosedGrade,
        uint256 disclosedCredits
    );
    
    event CredentialUnregistered(
        bytes32 indexed credentialHash,
        address indexed holder,
        uint256 timestamp
    );
    
    event RegistrarAdded(address indexed registrar);
    event RegistrarRemoved(address indexed registrar);
    event AnchorContractSet(address indexed anchorContract);
    event ZkVerifyContractSet(address indexed zkVerifyContract);
    event VkeySet(bytes32 indexed vkey);
    event ConstraintVkeySet(bytes32 indexed constraintVkey);
    
    // Errors
    error Unauthorized();
    error AlreadyRegistered();
    error NotRegistered();
    error InvalidAnchor();
    error HolderMismatch();
    error InvalidProof();
    error CredentialNotPublished();
    error CredentialRevoked();
    error CredentialExpired();
    error InvalidHolderAddress();
    error BatchSizeExceeded();
    error MaxCredentialsExceeded();
    
    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }
    
    modifier onlyTrustedRegistrar() {
        if (!trustedRegistrars[msg.sender] && msg.sender != owner) revert Unauthorized();
        _;
    }
    
    constructor(
        address _anchorContract,
        address _zkVerifyContract,
        bytes32 _vkey
    ) {
        owner = msg.sender;
        trustedRegistrars[msg.sender] = true;
        anchorContract = _anchorContract;
        zkVerifyContract = IVerifyProofAggregation(_zkVerifyContract);
        vkey = _vkey;
        constraintVkey = _vkey; // Default to same vkey, can be updated later
        emit AnchorContractSet(_anchorContract);
        emit ZkVerifyContractSet(_zkVerifyContract);
        emit VkeySet(_vkey);
        emit ConstraintVkeySet(_vkey);
    }
    
    /**
     * @notice Register a credential hash with a holder address
     * @param credentialHash Hash of the credential
     * @param holder Address of the credential holder
     * @param issuer Address of the credential issuer
     */
    function registerCredential(
        bytes32 credentialHash,
        address holder,
        address issuer
    ) external onlyTrustedRegistrar {
        if (registry[credentialHash].active) revert AlreadyRegistered();
        
        // Optional: Validate credential exists on Anchor contract
        if (anchorContract != address(0)) {
            (bool success, bytes memory data) = anchorContract.call(
                abi.encodeWithSignature("isPublished(bytes32)", credentialHash)
            );
            if (success) {
                bool isPublished = abi.decode(data, (bool));
                if (!isPublished) revert InvalidAnchor();
            }
        }
        
        // Create registry entry
        registry[credentialHash] = RegistryEntry({
            credentialHash: credentialHash,
            holder: holder,
            issuer: issuer,
            registeredAt: block.timestamp,
            active: true
        });
        
        // Check holder credential limit
        if (holderCredentials[holder].length >= MAX_CREDENTIALS_PER_HOLDER) {
            revert MaxCredentialsExceeded();
        }
        
        // Update mappings
        credentialHolder[credentialHash] = holder;
        holderCredentials[holder].push(credentialHash);
        
        emit CredentialRegistered(credentialHash, holder, issuer, block.timestamp);
    }
    
    /**
     * @notice Claim a credential directly with ZKP (no zkVerify aggregation)
     * @dev RESTRICTED TO TRUSTED REGISTRARS ONLY - This function does not verify ZKP on-chain
     * This is a trusted operation where the registrar has verified the proof off-chain
     * For trustless claiming, use claimCredential() with zkVerify aggregation
     * @param credentialHash Hash of the credential to claim
     * @param publicSignals Public signals: [credentialHash, holderAddress, isPublished, isRevoked, currentTimestamp, expiry]
     * @param issuer Address of the credential issuer (from Anchor contract, optional)
     */
    function claimCredentialDirect(
        bytes32 credentialHash,
        uint256[6] calldata publicSignals,
        address issuer
    ) external onlyTrustedRegistrar {
        if (registry[credentialHash].active) revert AlreadyRegistered();
        if (anchorContract == address(0)) revert InvalidAnchor();
        
        // Verify credential hash matches (public signal is uint256 from circuit)
        if (bytes32(publicSignals[0]) != credentialHash) revert InvalidProof();
        
        // Note: Holder address validation removed - trusted registrars can register on behalf of holders
        // The holder address in publicSignals[1] is validated by the ZKP proof
        
        // Verify credential is published on Anchor
        if (publicSignals[2] != 1) revert CredentialNotPublished();
        
        // Verify credential is not revoked
        if (publicSignals[3] != 0) revert CredentialRevoked();
        
        // Verify credential is not expired
        if (publicSignals[5] != 0 && publicSignals[4] > publicSignals[5]) revert CredentialExpired();
        
        // Double-check on Anchor contract (defense in depth)
        (bool success, bytes memory data) = anchorContract.call(
            abi.encodeWithSignature("isValid(bytes32)", credentialHash)
        );
        if (success && !abi.decode(data, (bool))) revert InvalidAnchor();
        
        // Get issuer from Anchor contract if not provided
        if (issuer == address(0)) {
            (success, data) = anchorContract.call(
                abi.encodeWithSignature("getCommit(bytes32)", credentialHash)
            );
            if (success) {
                // getCommit returns: (bool published, bool revoked, address issuer, ...)
                (,, issuer,,,) = abi.decode(data, (bool, bool, address, uint256, uint256, uint256));
            }
        }
        
        // Extract holder address from public signals (registrar is calling on behalf of holder)
        address holder = address(uint160(publicSignals[1]));
        
        // Check holder credential limit
        if (holderCredentials[holder].length >= MAX_CREDENTIALS_PER_HOLDER) {
            revert MaxCredentialsExceeded();
        }
        
        // Register the credential
        registry[credentialHash] = RegistryEntry({
            credentialHash: credentialHash,
            holder: holder,
            issuer: issuer,
            registeredAt: block.timestamp,
            active: true
        });
        
        // Update mappings
        credentialHolder[credentialHash] = holder;
        holderCredentials[holder].push(credentialHash);
        
        emit CredentialClaimed(credentialHash, holder, block.timestamp);
    }
    
    /**
     * @notice Claim a credential using a ZKP proving ownership via zkVerify aggregation
     * @dev Only the holder can claim their credential by proving they know the credential data
     * The proof must be submitted to zkVerify first to get aggregation data
     * @param credentialHash Hash of the credential to claim
     * @param publicSignals Public signals: [credentialHash, holderAddress, isPublished, isRevoked, currentTimestamp, expiry]
     * @param aggregationId Aggregation ID from zkVerify
     * @param domainId Domain ID from zkVerify
     * @param merklePath Merkle path for the aggregation proof
     * @param leafCount Total number of leaves in the aggregation
     * @param index Index of the leaf in the aggregation
     * @param issuer Address of the credential issuer (from Anchor contract, optional)
     */
    function claimCredential(
        bytes32 credentialHash,
        uint256[6] calldata publicSignals,
        uint256 aggregationId,
        uint256 domainId,
        bytes32[] calldata merklePath,
        uint256 leafCount,
        uint256 index,
        address issuer
    ) external {
        if (registry[credentialHash].active) revert AlreadyRegistered();
        if (anchorContract == address(0)) revert InvalidAnchor();
        if (address(zkVerifyContract) == address(0)) revert InvalidProof();
        
        // Verify credential hash matches
        if (bytes32(publicSignals[0]) != credentialHash) revert InvalidProof();
        
        // Verify holder address matches msg.sender (only holder can claim)
        if (address(uint160(publicSignals[1])) != msg.sender) revert InvalidHolderAddress();
        
        // Verify credential is published on Anchor
        if (publicSignals[2] != 1) revert CredentialNotPublished();
        
        // Verify credential is not revoked
        if (publicSignals[3] != 0) revert CredentialRevoked();
        
        // Verify credential is not expired
        if (publicSignals[5] != 0 && publicSignals[4] > publicSignals[5]) revert CredentialExpired();
        
        // Construct and verify leaf for zkVerify aggregation
        bytes32 leaf = _constructLeaf(publicSignals);
        if (!zkVerifyContract.verifyProofAggregation(domainId, aggregationId, leaf, merklePath, leafCount, index)) {
            revert InvalidProof();
        }
        
        // Double-check on Anchor contract (defense in depth)
        (bool success, bytes memory data) = anchorContract.call(
            abi.encodeWithSignature("isValid(bytes32)", credentialHash)
        );
        if (success && !abi.decode(data, (bool))) revert InvalidAnchor();
        
        // Get issuer from Anchor contract if not provided
        if (issuer == address(0)) {
            (success, data) = anchorContract.call(
                abi.encodeWithSignature("getCommit(bytes32)", credentialHash)
            );
            if (success) {
                // getCommit returns: (bool published, bool revoked, address issuer, ...)
                (,, issuer,,,) = abi.decode(data, (bool, bool, address, uint256, uint256, uint256));
            }
        }
        
        // Check holder credential limit
        if (holderCredentials[msg.sender].length >= MAX_CREDENTIALS_PER_HOLDER) {
            revert MaxCredentialsExceeded();
        }
        
        // Register the credential
        registry[credentialHash] = RegistryEntry({
            credentialHash: credentialHash,
            holder: msg.sender,
            issuer: issuer,
            registeredAt: block.timestamp,
            active: true
        });
        
        // Update mappings
        credentialHolder[credentialHash] = msg.sender;
        holderCredentials[msg.sender].push(credentialHash);
        
        emit CredentialClaimed(credentialHash, msg.sender, block.timestamp);
    }
    
    /**
     * @notice Claim a credential using envelope-based ZKP with selective disclosure (aggregated)
     * @dev This flow doesn't require the Anchor to know the holder's address
     * The issuer publishes a secretCommitment to Anchor, shares the envelope off-chain,
     * and the holder claims by proving knowledge of both credential data and secret
     * Holder can choose which fields to disclose publicly
     * @param credentialHash Poseidon hash of the credential data
     * @param publicSignals Public signals: [credentialHash, holderAddress, secretCommitment, currentTimestamp, 
     *                      disclosedCourseName, disclosedInstitution, disclosedCompletionDate, disclosedIssuanceDate, 
     *                      disclosedGrade, disclosedCredits, disclosureFlags]
     * @param aggregationId Aggregation ID from zkVerify
     * @param domainId Domain ID from zkVerify
     * @param merklePath Merkle path for the aggregation proof
     * @param leafCount Total number of leaves in the aggregation
     * @param index Index of the leaf in the aggregation
     */
    function claimCredentialWithEnvelope(
        bytes32 credentialHash,
        uint256[11] calldata publicSignals,
        uint256 aggregationId,
        uint256 domainId,
        bytes32[] calldata merklePath,
        uint256 leafCount,
        uint256 index
    ) external {
        if (registry[credentialHash].active) revert AlreadyRegistered();
        if (anchorContract == address(0)) revert InvalidAnchor();
        if (address(zkVerifyContract) == address(0)) revert InvalidProof();
        
        // Extract public signals with selective disclosure
        // 0: credentialHash, 1: holderAddress, 2: secretCommitment, 3: currentTimestamp
        // 4: disclosedCourseName, 5: disclosedInstitution, 6: disclosedCompletionDate
        // 7: disclosedIssuanceDate, 8: disclosedGrade, 9: disclosedCredits, 10: disclosureFlags
        bytes32 secretCommitment = bytes32(publicSignals[2]);
        
        // Verify credential hash matches
        if (bytes32(publicSignals[0]) != credentialHash) revert InvalidProof();
        
        // Verify holder address matches msg.sender (only holder can claim)
        if (address(uint160(publicSignals[1])) != msg.sender) revert InvalidHolderAddress();
        
        // Verify secret commitment hasn't been used before (prevent replay)
        if (usedSecretCommitments[secretCommitment]) revert AlreadyRegistered();
        
        // Construct and verify leaf for zkVerify aggregation
        bytes32 leaf = _constructEnvelopeLeaf(publicSignals);
        if (!zkVerifyContract.verifyProofAggregation(domainId, aggregationId, leaf, merklePath, leafCount, index)) {
            revert InvalidProof();
        }
        
        // Validate secretCommitment against Anchor contract
        (bool success, bytes memory data) = anchorContract.call(
            abi.encodeWithSignature("isValid(bytes32)", secretCommitment)
        );
        if (!success || !abi.decode(data, (bool))) revert InvalidAnchor();
        
        // Get issuer from Anchor contract
        address issuer;
        (success, data) = anchorContract.call(
            abi.encodeWithSignature("getCommit(bytes32)", secretCommitment)
        );
        if (!success) revert InvalidAnchor();
        
        // Verify data length is sufficient (6 * 32 bytes for the tuple)
        if (data.length < 192) revert InvalidAnchor();
        
        // getCommit returns: (bool published, bool revoked, address issuer, ...)
        (,, issuer,,,) = abi.decode(data, (bool, bool, address, uint256, uint256, uint256));
        
        // Verify issuer is not zero address
        if (issuer == address(0)) revert InvalidAnchor();
        
        // Check holder credential limit
        if (holderCredentials[msg.sender].length >= MAX_CREDENTIALS_PER_HOLDER) {
            revert MaxCredentialsExceeded();
        }
        
        // Register the credential
        registry[credentialHash] = RegistryEntry({
            credentialHash: credentialHash,
            holder: msg.sender,
            issuer: issuer,
            registeredAt: block.timestamp,
            active: true
        });
        
        // Update mappings
        credentialHolder[credentialHash] = msg.sender;
        holderCredentials[msg.sender].push(credentialHash);
        usedSecretCommitments[secretCommitment] = true;
        commitmentToCredential[secretCommitment] = credentialHash;
        
        // Emit event with disclosure information
        emit CredentialClaimedWithDisclosure(
            credentialHash,
            msg.sender,
            block.timestamp,
            publicSignals[10], // disclosureFlags
            publicSignals[4],  // disclosedCourseName
            publicSignals[5],  // disclosedInstitution
            publicSignals[6],  // disclosedCompletionDate
            publicSignals[7],  // disclosedIssuanceDate
            publicSignals[8], // disclosedGrade
            publicSignals[9]   // disclosedCredits
        );
    }
    
    /**
     * @notice Claim a credential using envelope-based ZKP with selective disclosure (direct, no zkVerify aggregation)
     * @dev RESTRICTED TO TRUSTED REGISTRARS ONLY - This function does not verify ZKP on-chain
     * This is a trusted operation where the registrar has verified the proof off-chain
     * For trustless claiming, use claimCredentialWithEnvelope() with zkVerify aggregation
     * @param credentialHash Poseidon hash of the credential data
     * @param publicSignals Public signals: [credentialHash, holderAddress, secretCommitment, currentTimestamp,
     *                      disclosedCourseName, disclosedInstitution, disclosedCompletionDate, disclosedIssuanceDate,
     *                      disclosedGrade, disclosedCredits, disclosureFlags]
     */
    function claimCredentialWithEnvelopeDirect(
        bytes32 credentialHash,
        uint256[11] calldata publicSignals
    ) external onlyTrustedRegistrar {
        if (registry[credentialHash].active) revert AlreadyRegistered();
        if (anchorContract == address(0)) revert InvalidAnchor();
        
        // Extract public signals with selective disclosure
        bytes32 secretCommitment = bytes32(publicSignals[2]);
        
        // Verify credential hash matches
        if (bytes32(publicSignals[0]) != credentialHash) revert InvalidProof();
        
        // Note: Holder address validation removed - trusted registrars can register on behalf of holders
        // The holder address in publicSignals[1] is validated by the ZKP proof
        
        // Verify secret commitment hasn't been used before (prevent replay)
        if (usedSecretCommitments[secretCommitment]) revert AlreadyRegistered();
        
        // Validate secretCommitment against Anchor contract
        (bool success, bytes memory data) = anchorContract.call(
            abi.encodeWithSignature("isValid(bytes32)", secretCommitment)
        );
        if (!success || !abi.decode(data, (bool))) revert InvalidAnchor();
        
        // Get issuer from Anchor contract
        address issuer;
        (success, data) = anchorContract.call(
            abi.encodeWithSignature("getCommit(bytes32)", secretCommitment)
        );
        if (!success) revert InvalidAnchor();
        
        // Verify data length is sufficient (6 * 32 bytes for the tuple)
        if (data.length < 192) revert InvalidAnchor();
        
        // getCommit returns: (bool published, bool revoked, address issuer, ...)
        (,, issuer,,,) = abi.decode(data, (bool, bool, address, uint256, uint256, uint256));
        
        // Verify issuer is not zero address
        if (issuer == address(0)) revert InvalidAnchor();
        
        // Extract holder address from public signals (registrar is calling on behalf of holder)
        address holder = address(uint160(publicSignals[1]));
        
        // Check holder credential limit
        if (holderCredentials[holder].length >= MAX_CREDENTIALS_PER_HOLDER) {
            revert MaxCredentialsExceeded();
        }
        
        // Register the credential
        registry[credentialHash] = RegistryEntry({
            credentialHash: credentialHash,
            holder: holder,
            issuer: issuer,
            registeredAt: block.timestamp,
            active: true
        });
        
        // Update mappings
        credentialHolder[credentialHash] = holder;
        holderCredentials[holder].push(credentialHash);
        usedSecretCommitments[secretCommitment] = true;
        commitmentToCredential[secretCommitment] = credentialHash;
        
        // Emit event with disclosure information
        emit CredentialClaimedWithDisclosure(
            credentialHash,
            holder,
            block.timestamp,
            publicSignals[10], // disclosureFlags
            publicSignals[4],  // disclosedCourseName
            publicSignals[5],  // disclosedInstitution
            publicSignals[6],  // disclosedCompletionDate
            publicSignals[7],  // disclosedIssuanceDate
            publicSignals[8], // disclosedGrade
            publicSignals[9]   // disclosedCredits
        );
    }
    
    /**
     * @notice Verify a constraint proof via zkVerify aggregation
     * @dev Verifies that a credential satisfies certain constraints (e.g., grade >= 80) without revealing the actual values
     * @param credentialHash Hash of the credential being verified
     * @param aggregationId Aggregation ID from zkVerify
     * @param domainId Domain ID from zkVerify
     * @param merklePath Merkle path for the aggregation proof
     * @param leafCount Total number of leaves in the aggregation
     * @param index Index of the leaf in the aggregation
     * @param publicSignals Public signals from the constraint proof: [credentialHash, holderAddress, secretCommitment, constraintMask, ...constraintValues]
     * @return True if the constraint proof is valid
     */
    function verifyConstraintProof(
        bytes32 credentialHash,
        uint256 aggregationId,
        uint256 domainId,
        bytes32[] calldata merklePath,
        uint256 leafCount,
        uint256 index,
        uint256[] calldata publicSignals
    ) external view returns (bool) {
        // Verify credential is registered and active
        RegistryEntry memory entry = registry[credentialHash];
        if (!entry.active) revert NotRegistered();
        
        // Verify holder address matches (from public signals)
        if (publicSignals.length < 2) revert InvalidProof();
        address holder = address(uint160(publicSignals[1]));
        if (entry.holder != holder) revert HolderMismatch();
        
        // Construct leaf from constraint proof public signals
        bytes32 leaf = _constructConstraintLeaf(publicSignals);
        
        // Verify proof aggregation via zkVerify
        if (!zkVerifyContract.verifyProofAggregation(domainId, aggregationId, leaf, merklePath, leafCount, index)) {
            revert InvalidProof();
        }
        
        return true;
    }
    
    /**
     * @notice Construct leaf digest for constraint proof verification
     * @param publicSignals Public signals: [credentialHash, holderAddress, secretCommitment, constraintMask, ...constraintValues]
     * @return leaf The constructed leaf digest
     */
    function _constructConstraintLeaf(uint256[] calldata publicSignals) internal view returns (bytes32) {
        // Construct public inputs hash with endianness conversion for hash-like signals
        bytes memory publicInputsData;
        
        // First 3 signals are hash-like (credentialHash, holderAddress, secretCommitment)
        for (uint256 i = 0; i < 3 && i < publicSignals.length; i++) {
            publicInputsData = abi.encodePacked(publicInputsData, _changeEndianess(publicSignals[i]));
        }
        
        // Remaining signals are regular values (constraintMask, constraintValues)
        for (uint256 i = 3; i < publicSignals.length; i++) {
            publicInputsData = abi.encodePacked(publicInputsData, publicSignals[i]);
        }
        
        bytes32 publicInputsHash = keccak256(publicInputsData);
        
        // Construct leaf: keccak256(PROVING_SYSTEM_ID || constraintVkey || VERSION_HASH || publicInputsHash)
        return keccak256(abi.encodePacked(
            PROVING_SYSTEM_ID,
            constraintVkey,
            VERSION_HASH,
            publicInputsHash
        ));
    }
    
    /**
     * @notice Construct leaf digest for zkVerify aggregation verification (envelope flow with selective disclosure)
     * @param publicSignals Public signals: [credentialHash, holderAddress, secretCommitment, currentTimestamp,
     *                      disclosedCourseName, disclosedInstitution, disclosedCompletionDate, disclosedIssuanceDate,
     *                      disclosedGrade, disclosedCredits, disclosureFlags]
     * @return leaf The constructed leaf digest
     */
    function _constructEnvelopeLeaf(uint256[11] calldata publicSignals) internal view returns (bytes32) {
        // Construct public inputs hash with endianness conversion for hash-like signals
        bytes32 publicInputsHash = keccak256(abi.encodePacked(
            _changeEndianess(publicSignals[0]),  // credentialHash
            _changeEndianess(publicSignals[1]),  // holderAddress
            _changeEndianess(publicSignals[2]),  // secretCommitment
            publicSignals[3],   // currentTimestamp
            publicSignals[4],   // disclosedCourseName
            publicSignals[5],   // disclosedInstitution
            publicSignals[6],   // disclosedCompletionDate
            publicSignals[7],   // disclosedIssuanceDate
            publicSignals[8],   // disclosedGrade
            publicSignals[9],   // disclosedCredits
            publicSignals[10]   // disclosureFlags
        ));
        
        // Construct leaf: keccak256(PROVING_SYSTEM_ID || vkey || VERSION_HASH || publicInputsHash)
        return keccak256(abi.encodePacked(
            PROVING_SYSTEM_ID,
            vkey,
            VERSION_HASH,
            publicInputsHash
        ));
    }
    
    /**
     * @notice Construct leaf digest for zkVerify aggregation verification
     * @param publicSignals Public signals: [credentialHash, holderAddress, isPublished, isRevoked, currentTimestamp, expiry]
     * @return leaf The constructed leaf digest
     */
    function _constructLeaf(uint256[6] calldata publicSignals) internal view returns (bytes32) {
        // Construct public inputs hash with endianness conversion for first two signals
        bytes32 publicInputsHash = keccak256(abi.encodePacked(
            _changeEndianess(publicSignals[0]),  // credentialHash
            _changeEndianess(publicSignals[1]),  // holderAddress
            publicSignals[2],  // isPublished
            publicSignals[3],  // isRevoked
            publicSignals[4],  // currentTimestamp
            publicSignals[5]   // expiry
        ));
        
        // Construct leaf: keccak256(PROVING_SYSTEM_ID || vkey || VERSION_HASH || publicInputsHash)
        return keccak256(abi.encodePacked(
            PROVING_SYSTEM_ID,
            vkey,
            VERSION_HASH,
            publicInputsHash
        ));
    }
    
    /**
     * @notice Change endianness of a uint256 (for Groth16 public inputs)
     * @dev Groth16 uses big-endian, but Solidity uses little-endian
     * @param input The input value to convert
     * @return v The value with changed endianness
     */
    function _changeEndianess(uint256 input) internal pure returns (uint256 v) {
        v = input;
        // swap bytes
        v = ((v & 0xFF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00) >> 8) |
            ((v & 0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF) << 8);
        // swap 2-byte long pairs
        v = ((v & 0xFFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000) >> 16) |
            ((v & 0x0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF) << 16);
        // swap 4-byte long pairs
        v = ((v & 0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000) >> 32) |
            ((v & 0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF) << 32);
        // swap 8-byte long pairs
        v = ((v & 0xFFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF0000000000000000) >> 64) |
            ((v & 0x0000000000000000FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF) << 64);
        // swap 16-byte long pairs
        v = (v >> 128) | (v << 128);
    }
    
    /**
     * @notice Unregister a credential (marks as inactive)
     * @param credentialHash Hash of the credential
     */
    function unregisterCredential(bytes32 credentialHash) external onlyTrustedRegistrar {
        RegistryEntry storage entry = registry[credentialHash];
        
        if (!entry.active) revert NotRegistered();
        
        entry.active = false;
        
        emit CredentialUnregistered(credentialHash, entry.holder, block.timestamp);
    }
    
    /**
     * @notice Get holder address for a credential hash
     * @param credentialHash Hash of the credential
     * @return holder Address of the holder (address(0) if not registered)
     */
    function getHolder(bytes32 credentialHash) external view returns (address holder) {
        RegistryEntry memory entry = registry[credentialHash];
        if (!entry.active) return address(0);
        return entry.holder;
    }
    
    /**
     * @notice Get all credential hashes for a holder
     * @param holder Address of the holder
     * @return credentialHashes Array of credential hashes
     */
    function getHolderCredentials(address holder) external view returns (bytes32[] memory credentialHashes) {
        return holderCredentials[holder];
    }
    
    /**
     * @notice Get active credential hashes for a holder
     * @param holder Address of the holder
     * @return activeHashes Array of active credential hashes
     */
    function getActiveHolderCredentials(address holder) external view returns (bytes32[] memory activeHashes) {
        bytes32[] memory allHashes = holderCredentials[holder];
        uint256 activeCount = 0;
        
        // Count active credentials
        for (uint256 i = 0; i < allHashes.length; i++) {
            if (registry[allHashes[i]].active) {
                activeCount++;
            }
        }
        
        // Build array of active hashes
        activeHashes = new bytes32[](activeCount);
        uint256 index = 0;
        for (uint256 i = 0; i < allHashes.length; i++) {
            if (registry[allHashes[i]].active) {
                activeHashes[index] = allHashes[i];
                index++;
            }
        }
        
        return activeHashes;
    }
    
    /**
     * @notice Get registry entry for a credential hash
     * @param credentialHash Hash of the credential
     * @return hash The credential hash
     * @return holder The holder address
     * @return issuer The issuer address
     * @return registeredAt Timestamp when registered
     * @return active Whether the credential is active
     */
    function getRegistryEntry(bytes32 credentialHash)
        external
        view
        returns (
            bytes32 hash,
            address holder,
            address issuer,
            uint256 registeredAt,
            bool active
        )
    {
        RegistryEntry memory entry = registry[credentialHash];
        return (
            entry.credentialHash,
            entry.holder,
            entry.issuer,
            entry.registeredAt,
            entry.active
        );
    }
    
    /**
     * @notice Check if a credential is registered and active
     * @param credentialHash Hash of the credential
     * @return True if registered and active
     */
    function isRegistered(bytes32 credentialHash) external view returns (bool) {
        return registry[credentialHash].active;
    }
    
    /**
     * @notice Check if a holder owns a specific credential
     * @param holder Address of the holder
     * @param credentialHash Hash of the credential
     * @return owns True if holder owns the credential
     */
    function holderOwnsCredential(address holder, bytes32 credentialHash)
        external
        view
        returns (bool owns)
    {
        RegistryEntry memory entry = registry[credentialHash];
        return entry.active && entry.holder == holder;
    }
    
    /**
     * @notice Add a trusted registrar
     * @param registrar Address of the registrar
     */
    function addRegistrar(address registrar) external onlyOwner {
        trustedRegistrars[registrar] = true;
        emit RegistrarAdded(registrar);
    }
    
    /**
     * @notice Remove a trusted registrar
     * @param registrar Address of the registrar
     */
    function removeRegistrar(address registrar) external onlyOwner {
        trustedRegistrars[registrar] = false;
        emit RegistrarRemoved(registrar);
    }
    
    /**
     * @notice Set the anchor contract address
     * @param _anchorContract Address of the Anchor contract
     */
    function setAnchorContract(address _anchorContract) external onlyOwner {
        anchorContract = _anchorContract;
        emit AnchorContractSet(_anchorContract);
    }
    
    /**
     * @notice Set the zkVerify contract address
     * @param _zkVerifyContract Address of the zkVerify aggregation contract
     */
    function setZkVerifyContract(address _zkVerifyContract) external onlyOwner {
        zkVerifyContract = IVerifyProofAggregation(_zkVerifyContract);
        emit ZkVerifyContractSet(_zkVerifyContract);
    }
    
    /**
     * @notice Set the verification key hash
     * @param _vkey Hash of the verification key for the credential ownership circuit
     */
    function setVkey(bytes32 _vkey) external onlyOwner {
        vkey = _vkey;
        emit VkeySet(_vkey);
    }
    
    /**
     * @notice Set the constraint circuit verification key hash
     * @param _constraintVkey Hash of the verification key for the constraint circuit
     */
    function setConstraintVkey(bytes32 _constraintVkey) external onlyOwner {
        constraintVkey = _constraintVkey;
        emit ConstraintVkeySet(_constraintVkey);
    }
    
    /**
     * @notice Batch register multiple credentials
     * @param credentialHashes Array of credential hashes
     * @param holders Array of holder addresses
     * @param issuers Array of issuer addresses
     */
    function batchRegisterCredentials(
        bytes32[] calldata credentialHashes,
        address[] calldata holders,
        address[] calldata issuers
    ) external onlyTrustedRegistrar {
        if (credentialHashes.length == 0) revert AlreadyRegistered();
        if (credentialHashes.length > MAX_BATCH_SIZE) revert BatchSizeExceeded();
        
        require(
            credentialHashes.length == holders.length &&
            credentialHashes.length == issuers.length,
            "Array length mismatch"
        );
        
        for (uint256 i = 0; i < credentialHashes.length; i++) {
            if (!registry[credentialHashes[i]].active) {
                // Check holder credential limit
                if (holderCredentials[holders[i]].length >= MAX_CREDENTIALS_PER_HOLDER) {
                    revert MaxCredentialsExceeded();
                }
                
                registry[credentialHashes[i]] = RegistryEntry({
                    credentialHash: credentialHashes[i],
                    holder: holders[i],
                    issuer: issuers[i],
                    registeredAt: block.timestamp,
                    active: true
                });
                
                credentialHolder[credentialHashes[i]] = holders[i];
                holderCredentials[holders[i]].push(credentialHashes[i]);
                
                emit CredentialRegistered(
                    credentialHashes[i],
                    holders[i],
                    issuers[i],
                    block.timestamp
                );
            }
        }
    }
}

