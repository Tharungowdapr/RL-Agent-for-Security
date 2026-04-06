import random
from typing import List
from env.models import CompanyAsset

ASSET_TEMPLATES = [
    {
        "asset_id": "ASSET-001",
        "name": "Payment Processing Server",
        "software": ["apache httpd", "mysql", "openssl"],
        "criticality": "CRITICAL",
        "criticality_score": 10.0,
        "description": "Handles all payment transactions"
    },
    {
        "asset_id": "ASSET-002",
        "name": "Customer Database",
        "software": ["postgresql", "linux kernel", "openssl"],
        "criticality": "CRITICAL",
        "criticality_score": 9.5,
        "description": "Stores PII and customer records"
    },
    {
        "asset_id": "ASSET-003",
        "name": "Auth Service",
        "software": ["openssh", "python flask", "nginx"],
        "criticality": "HIGH",
        "criticality_score": 8.5,
        "description": "Handles SSO and user authentication"
    },
    {
        "asset_id": "ASSET-004",
        "name": "Internal API Gateway",
        "software": ["nginx", "nodejs express", "redis"],
        "criticality": "HIGH",
        "criticality_score": 7.5,
        "description": "Routes internal microservice traffic"
    },
    {
        "asset_id": "ASSET-005",
        "name": "Dev/Staging Server",
        "software": ["python django", "postgresql", "curl"],
        "criticality": "LOW",
        "criticality_score": 2.0,
        "description": "Non-production staging environment"
    },
    {
        "asset_id": "ASSET-006",
        "name": "Logging Service",
        "software": ["nodejs express", "redis", "linux kernel"],
        "criticality": "MEDIUM",
        "criticality_score": 5.0,
        "description": "Aggregates application logs"
    },
    {
        "asset_id": "ASSET-007",
        "name": "ML Training Cluster",
        "software": ["kubernetes", "python flask", "linux kernel"],
        "criticality": "MEDIUM",
        "criticality_score": 5.5,
        "description": "Internal ML model training jobs"
    },
    {
        "asset_id": "ASSET-008",
        "name": "Public Web Server",
        "software": ["apache httpd", "nginx", "openssl"],
        "criticality": "HIGH",
        "criticality_score": 8.0,
        "description": "Serves public-facing website"
    },
    {
        "asset_id": "ASSET-009",
        "name": "Backup System",
        "software": ["linux kernel", "curl", "openssh"],
        "criticality": "MEDIUM",
        "criticality_score": 6.0,
        "description": "Automated backup and recovery"
    },
    {
        "asset_id": "ASSET-010",
        "name": "Spring Boot Microservice",
        "software": ["spring boot", "mysql", "redis"],
        "criticality": "HIGH",
        "criticality_score": 8.2,
        "description": "Core business logic microservice"
    }
]


def generate_assets(count: int = 10) -> List[CompanyAsset]:
    assets = ASSET_TEMPLATES[:count]
    return [CompanyAsset(**a) for a in assets]


def get_affected_assets(cve_software: List[str], assets: List[CompanyAsset]) -> List[str]:
    affected = []
    for asset in assets:
        for soft in asset.software:
            for cve_soft in cve_software:
                if any(word in soft.lower() for word in cve_soft.lower().split()):
                    affected.append(asset.asset_id)
                    break
    return list(set(affected))
