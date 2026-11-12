// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Реестр цифровых сертификатов: единый источник достоверного состояния
contract CertificateRegistry {
    address public admin;
    mapping(address => bool) public issuers;

    struct Cert { bytes32 hash; bytes32 opId; uint8 status; uint64 ts; } // 1=ISSUED, 2=REVOKED
    mapping(bytes32 => Cert) public certs;
    mapping(bytes32 => bool) public usedOps;

    event CertificateIssued(bytes32 indexed certId, bytes32 hash, bytes32 indexed opId, address issuer);
    event CertificateRevoked(bytes32 indexed certId, bytes32 indexed opId);

    modifier onlyAdmin() { require(msg.sender == admin, "NOT_ADMIN"); _; }
    modifier onlyIssuer() { require(issuers[msg.sender], "NOT_ISSUER"); _; }

    constructor() { admin = msg.sender; }

    function setIssuer(address a, bool v) external onlyAdmin { issuers[a] = v; }

    function issue(bytes32 certId, bytes32 hash, bytes32 opId) external onlyIssuer {
        require(!usedOps[opId], "DUP_OP");
        require(certs[certId].status == 0, "CERT_EXISTS");
        require(hash != bytes32(0), "EMPTY_HASH");
        usedOps[opId] = true;
        certs[certId] = Cert(hash, opId, 1, uint64(block.timestamp));
        emit CertificateIssued(certId, hash, opId, msg.sender);
    }

    function revoke(bytes32 certId, bytes32 opId) external onlyIssuer {
        require(!usedOps[opId], "DUP_OP");
        require(certs[certId].status == 1, "NOT_ISSUED");
        usedOps[opId] = true;
        certs[certId].status = 2;
        emit CertificateRevoked(certId, opId);
    }

    function verify(bytes32 certId, bytes32 hash) external view returns (bool) {
        Cert memory c = certs[certId];
        return c.status == 1 && c.hash == hash;
    }
}
