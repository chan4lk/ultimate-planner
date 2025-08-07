"""
Comprehensive Audit Logging Service for Security and Compliance
SOC 2, GDPR, and enterprise security audit trail implementation
"""

import json
import time
import uuid
from typing import Dict, Any, Optional, List, Union
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, asdict
import hashlib

from app.config.redis_config import get_redis_client
from app.core.logging import get_logger

logger = get_logger(__name__)

class AuditEventType(str, Enum):
    """Audit event types for comprehensive logging"""
    # Authentication Events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    MFA_VERIFICATION_SUCCESS = "mfa_verification_success"
    MFA_VERIFICATION_FAILURE = "mfa_verification_failure"
    
    # Session Management
    SESSION_CREATED = "session_created"
    SESSION_TERMINATED = "session_terminated"
    SESSION_EXPIRED = "session_expired"
    TOKEN_REFRESHED = "token_refreshed"
    TOKEN_REVOKED = "token_revoked"
    
    # OAuth Events
    OAUTH_AUTHORIZATION_START = "oauth_authorization_start"
    OAUTH_AUTHORIZATION_SUCCESS = "oauth_authorization_success"
    OAUTH_AUTHORIZATION_FAILURE = "oauth_authorization_failure"
    PKCE_GENERATED = "pkce_generated"
    PKCE_VALIDATED = "pkce_validated"
    
    # Account Management
    ACCOUNT_CREATED = "account_created"
    ACCOUNT_UPDATED = "account_updated"
    ACCOUNT_DELETED = "account_deleted"
    PASSWORD_CHANGED = "password_changed"
    PASSWORD_RESET_REQUESTED = "password_reset_requested"
    PASSWORD_RESET_COMPLETED = "password_reset_completed"
    EMAIL_VERIFIED = "email_verified"
    
    # Security Events
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    UNAUTHORIZED_ACCESS_ATTEMPT = "unauthorized_access_attempt"
    PRIVILEGE_ESCALATION_ATTEMPT = "privilege_escalation_attempt"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    DATA_DELETION = "data_deletion"
    
    # System Events
    SYSTEM_CONFIG_CHANGED = "system_config_changed"
    SECURITY_POLICY_UPDATED = "security_policy_updated"
    BACKUP_CREATED = "backup_created"
    BACKUP_RESTORED = "backup_restored"

class AuditSeverity(str, Enum):
    """Audit event severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class AuditEvent:
    """Audit event data structure"""
    event_id: str
    event_type: AuditEventType
    severity: AuditSeverity
    timestamp: datetime
    user_id: Optional[str]
    session_id: Optional[str]
    ip_address: Optional[str]
    user_agent: Optional[str]
    resource: Optional[str]
    action: str
    outcome: str  # SUCCESS, FAILURE, PENDING
    details: Dict[str, Any]
    risk_score: Optional[int]  # 0-100
    compliance_tags: List[str]

class ComplianceStandard(str, Enum):
    """Compliance standards for audit categorization"""
    SOC2_TYPE_II = "soc2_type_ii"
    GDPR = "gdpr"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    NIST_CSF = "nist_csf"
    ISO_27001 = "iso_27001"

class AuditLoggingService:
    """
    Comprehensive audit logging service for security and compliance
    """
    
    def __init__(self):
        self.redis_client = None
        
        # Event severity mapping
        self.severity_mapping = {
            AuditEventType.LOGIN_FAILURE: AuditSeverity.MEDIUM,
            AuditEventType.MFA_VERIFICATION_FAILURE: AuditSeverity.MEDIUM,
            AuditEventType.SUSPICIOUS_ACTIVITY: AuditSeverity.HIGH,
            AuditEventType.RATE_LIMIT_EXCEEDED: AuditSeverity.HIGH,
            AuditEventType.UNAUTHORIZED_ACCESS_ATTEMPT: AuditSeverity.HIGH,
            AuditEventType.PRIVILEGE_ESCALATION_ATTEMPT: AuditSeverity.CRITICAL,
            AuditEventType.ACCOUNT_DELETED: AuditSeverity.HIGH,
            AuditEventType.PASSWORD_CHANGED: AuditSeverity.MEDIUM,
            AuditEventType.SYSTEM_CONFIG_CHANGED: AuditSeverity.HIGH,
        }
        
        # Compliance tag mapping
        self.compliance_mapping = {
            # SOC 2 Type II Requirements
            AuditEventType.LOGIN_SUCCESS: [ComplianceStandard.SOC2_TYPE_II, ComplianceStandard.NIST_CSF],
            AuditEventType.LOGIN_FAILURE: [ComplianceStandard.SOC2_TYPE_II, ComplianceStandard.NIST_CSF],
            AuditEventType.MFA_ENABLED: [ComplianceStandard.SOC2_TYPE_II, ComplianceStandard.NIST_CSF],
            AuditEventType.DATA_ACCESS: [ComplianceStandard.SOC2_TYPE_II, ComplianceStandard.GDPR],
            AuditEventType.DATA_MODIFICATION: [ComplianceStandard.SOC2_TYPE_II, ComplianceStandard.GDPR],
            AuditEventType.DATA_DELETION: [ComplianceStandard.SOC2_TYPE_II, ComplianceStandard.GDPR],
            AuditEventType.ACCOUNT_CREATED: [ComplianceStandard.GDPR, ComplianceStandard.SOC2_TYPE_II],
            AuditEventType.ACCOUNT_DELETED: [ComplianceStandard.GDPR, ComplianceStandard.SOC2_TYPE_II],
            AuditEventType.PASSWORD_CHANGED: [ComplianceStandard.SOC2_TYPE_II, ComplianceStandard.NIST_CSF],
            AuditEventType.SYSTEM_CONFIG_CHANGED: [ComplianceStandard.SOC2_TYPE_II, ComplianceStandard.ISO_27001],
        }
    
    async def _get_redis(self):
        """Get Redis client with lazy initialization"""
        if self.redis_client is None:
            self.redis_client = await get_redis_client()
        return self.redis_client
    
    def _calculate_risk_score(
        self, 
        event_type: AuditEventType, 
        outcome: str, 
        details: Dict[str, Any]
    ) -> int:
        """
        Calculate risk score for audit event (0-100)
        
        Args:
            event_type: Type of audit event
            outcome: Event outcome (SUCCESS, FAILURE, PENDING)
            details: Event details for risk calculation
            
        Returns:
            Risk score between 0 and 100
        """
        base_score = 0
        
        # Base scores by event type
        base_scores = {
            AuditEventType.LOGIN_FAILURE: 30,
            AuditEventType.MFA_VERIFICATION_FAILURE: 40,
            AuditEventType.SUSPICIOUS_ACTIVITY: 70,
            AuditEventType.RATE_LIMIT_EXCEEDED: 60,
            AuditEventType.UNAUTHORIZED_ACCESS_ATTEMPT: 80,
            AuditEventType.PRIVILEGE_ESCALATION_ATTEMPT: 95,
            AuditEventType.DATA_DELETION: 50,
            AuditEventType.SYSTEM_CONFIG_CHANGED: 40,
        }
        
        base_score = base_scores.get(event_type, 10)
        
        # Adjust based on outcome
        if outcome == "FAILURE":
            base_score += 20
        elif outcome == "SUCCESS" and event_type in [
            AuditEventType.UNAUTHORIZED_ACCESS_ATTEMPT,
            AuditEventType.PRIVILEGE_ESCALATION_ATTEMPT
        ]:
            base_score += 30
        
        # Adjust based on details
        if details.get("repeated_attempts", 0) > 5:
            base_score += 20
        
        if details.get("from_new_ip", False):
            base_score += 15
        
        if details.get("admin_action", False):
            base_score += 10
        
        return min(100, max(0, base_score))
    
    async def log_event(
        self,
        event_type: AuditEventType,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        resource: Optional[str] = None,
        action: str = "",
        outcome: str = "SUCCESS",
        details: Dict[str, Any] = None,
        custom_severity: Optional[AuditSeverity] = None
    ) -> str:
        """
        Log an audit event
        
        Args:
            event_type: Type of audit event
            user_id: User identifier
            session_id: Session identifier
            ip_address: Client IP address
            user_agent: Client user agent
            resource: Resource being accessed/modified
            action: Specific action performed
            outcome: Event outcome (SUCCESS, FAILURE, PENDING)
            details: Additional event details
            custom_severity: Override default severity
            
        Returns:
            Audit event ID
        """
        try:
            redis = await self._get_redis()
            
            # Generate event ID and timestamp
            event_id = str(uuid.uuid4())
            timestamp = datetime.utcnow()
            
            # Determine severity
            severity = custom_severity or self.severity_mapping.get(
                event_type, AuditSeverity.LOW
            )
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(event_type, outcome, details or {})
            
            # Get compliance tags
            compliance_tags = [
                tag.value for tag in self.compliance_mapping.get(event_type, [])
            ]
            
            # Create audit event
            audit_event = AuditEvent(
                event_id=event_id,
                event_type=event_type,
                severity=severity,
                timestamp=timestamp,
                user_id=user_id,
                session_id=session_id,
                ip_address=ip_address,
                user_agent=user_agent,
                resource=resource,
                action=action,
                outcome=outcome,
                details=details or {},
                risk_score=risk_score,
                compliance_tags=compliance_tags
            )
            
            # Serialize event
            event_data = {
                **asdict(audit_event),
                "timestamp": timestamp.isoformat()
            }
            
            # Store event with multiple indices for efficient querying
            current_timestamp = int(time.time())
            
            # Primary storage
            event_key = f"audit:event:{event_id}"
            await redis.setex(event_key, 86400 * 365 * 7, json.dumps(event_data))  # 7 years retention
            
            # Time-based index
            time_index = f"audit:index:time:{timestamp.strftime('%Y-%m-%d')}"
            await redis.zadd(time_index, {event_id: current_timestamp})
            await redis.expire(time_index, 86400 * 365 * 7)
            
            # User-based index
            if user_id:
                user_index = f"audit:index:user:{user_id}"
                await redis.zadd(user_index, {event_id: current_timestamp})
                await redis.expire(user_index, 86400 * 365 * 2)  # 2 years for user events
            
            # Event type index
            type_index = f"audit:index:type:{event_type.value}"
            await redis.zadd(type_index, {event_id: current_timestamp})
            await redis.expire(type_index, 86400 * 365 * 7)
            
            # Severity index
            severity_index = f"audit:index:severity:{severity.value}"
            await redis.zadd(severity_index, {event_id: current_timestamp})
            await redis.expire(severity_index, 86400 * 365 * 7)
            
            # Risk score index
            if risk_score >= 70:  # High risk events
                risk_index = "audit:index:high_risk"
                await redis.zadd(risk_index, {event_id: current_timestamp})
                await redis.expire(risk_index, 86400 * 365 * 7)
            
            # Compliance indices
            for tag in compliance_tags:
                compliance_index = f"audit:index:compliance:{tag}"
                await redis.zadd(compliance_index, {event_id: current_timestamp})
                await redis.expire(compliance_index, 86400 * 365 * 7)
            
            logger.info(f"Audit event logged: {event_type.value} (ID: {event_id}, Risk: {risk_score})")
            
            # Trigger real-time alerts for critical events
            if severity == AuditSeverity.CRITICAL or risk_score >= 90:
                await self._trigger_security_alert(audit_event)
            
            return event_id
            
        except Exception as e:
            logger.error(f"Failed to log audit event: {str(e)}")
            raise
    
    async def get_audit_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        user_id: Optional[str] = None,
        event_types: Optional[List[AuditEventType]] = None,
        severity: Optional[AuditSeverity] = None,
        compliance_standard: Optional[ComplianceStandard] = None,
        min_risk_score: Optional[int] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Query audit events with multiple filter options
        
        Args:
            start_time: Start time for query
            end_time: End time for query
            user_id: Filter by user ID
            event_types: Filter by event types
            severity: Filter by severity
            compliance_standard: Filter by compliance standard
            min_risk_score: Minimum risk score filter
            limit: Maximum number of events to return
            offset: Offset for pagination
            
        Returns:
            List of audit events
        """
        try:
            redis = await self._get_redis()
            
            # Determine query strategy based on filters
            if user_id:
                index_key = f"audit:index:user:{user_id}"
            elif severity:
                index_key = f"audit:index:severity:{severity.value}"
            elif compliance_standard:
                index_key = f"audit:index:compliance:{compliance_standard.value}"
            elif min_risk_score and min_risk_score >= 70:
                index_key = "audit:index:high_risk"
            else:
                # Use time-based query
                if start_time:
                    start_date = start_time.strftime('%Y-%m-%d')
                    index_key = f"audit:index:time:{start_date}"
                else:
                    # Default to today
                    index_key = f"audit:index:time:{datetime.utcnow().strftime('%Y-%m-%d')}"
            
            # Get event IDs from index
            if start_time and end_time:
                start_timestamp = int(start_time.timestamp())
                end_timestamp = int(end_time.timestamp())
                event_ids = await redis.zrangebyscore(
                    index_key, start_timestamp, end_timestamp, 
                    offset=offset, count=limit
                )
            else:
                event_ids = await redis.zrevrange(
                    index_key, offset, offset + limit - 1
                )
            
            # Fetch event data
            events = []
            for event_id in event_ids:
                event_key = f"audit:event:{event_id.decode() if isinstance(event_id, bytes) else event_id}"
                event_data = await redis.get(event_key)
                
                if event_data:
                    try:
                        event = json.loads(event_data)
                        
                        # Apply additional filters
                        if event_types and event["event_type"] not in [et.value for et in event_types]:
                            continue
                        
                        if min_risk_score and event.get("risk_score", 0) < min_risk_score:
                            continue
                        
                        events.append(event)
                        
                    except Exception as e:
                        logger.error(f"Error parsing audit event {event_id}: {str(e)}")
                        continue
            
            return events
            
        except Exception as e:
            logger.error(f"Failed to query audit events: {str(e)}")
            return []
    
    async def get_compliance_report(
        self,
        compliance_standard: ComplianceStandard,
        start_time: datetime,
        end_time: datetime
    ) -> Dict[str, Any]:
        """
        Generate compliance report for audit events
        
        Args:
            compliance_standard: Compliance standard to report on
            start_time: Report start time
            end_time: Report end time
            
        Returns:
            Compliance report dictionary
        """
        try:
            # Get all events for compliance standard
            events = await self.get_audit_events(
                start_time=start_time,
                end_time=end_time,
                compliance_standard=compliance_standard,
                limit=10000
            )
            
            # Analyze events
            report = {
                "compliance_standard": compliance_standard.value,
                "report_period": {
                    "start": start_time.isoformat(),
                    "end": end_time.isoformat()
                },
                "total_events": len(events),
                "events_by_type": {},
                "events_by_severity": {},
                "high_risk_events": [],
                "failed_events": [],
                "summary": {}
            }
            
            # Categorize events
            for event in events:
                event_type = event.get("event_type", "unknown")
                severity = event.get("severity", "low")
                outcome = event.get("outcome", "SUCCESS")
                risk_score = event.get("risk_score", 0)
                
                # Count by type
                report["events_by_type"][event_type] = report["events_by_type"].get(event_type, 0) + 1
                
                # Count by severity
                report["events_by_severity"][severity] = report["events_by_severity"].get(severity, 0) + 1
                
                # High risk events
                if risk_score >= 70:
                    report["high_risk_events"].append({
                        "event_id": event["event_id"],
                        "event_type": event_type,
                        "timestamp": event["timestamp"],
                        "risk_score": risk_score,
                        "outcome": outcome
                    })
                
                # Failed events
                if outcome == "FAILURE":
                    report["failed_events"].append({
                        "event_id": event["event_id"],
                        "event_type": event_type,
                        "timestamp": event["timestamp"],
                        "details": event.get("details", {})
                    })
            
            # Generate summary
            report["summary"] = {
                "authentication_events": report["events_by_type"].get("login_success", 0) + 
                                       report["events_by_type"].get("login_failure", 0),
                "mfa_events": report["events_by_type"].get("mfa_enabled", 0) + 
                            report["events_by_type"].get("mfa_verification_success", 0),
                "data_access_events": report["events_by_type"].get("data_access", 0),
                "security_violations": len(report["high_risk_events"]),
                "failure_rate": len(report["failed_events"]) / max(1, len(events)) * 100
            }
            
            return report
            
        except Exception as e:
            logger.error(f"Failed to generate compliance report: {str(e)}")
            return {"error": str(e)}
    
    async def _trigger_security_alert(self, audit_event: AuditEvent) -> None:
        """
        Trigger real-time security alert for critical events
        
        Args:
            audit_event: Critical audit event
        """
        try:
            redis = await self._get_redis()
            
            alert_data = {
                "alert_id": str(uuid.uuid4()),
                "timestamp": datetime.utcnow().isoformat(),
                "event_id": audit_event.event_id,
                "event_type": audit_event.event_type.value,
                "severity": audit_event.severity.value,
                "risk_score": audit_event.risk_score,
                "user_id": audit_event.user_id,
                "ip_address": audit_event.ip_address,
                "details": audit_event.details,
                "status": "ACTIVE"
            }
            
            # Store alert
            alert_key = f"security:alert:{alert_data['alert_id']}"
            await redis.setex(alert_key, 86400 * 30, json.dumps(alert_data))  # 30 days
            
            # Add to active alerts index
            await redis.zadd("security:alerts:active", {alert_data["alert_id"]: time.time()})
            
            logger.critical(f"Security alert triggered: {audit_event.event_type.value} (Risk: {audit_event.risk_score})")
            
            # TODO: Integrate with external alerting systems (email, Slack, PagerDuty, etc.)
            
        except Exception as e:
            logger.error(f"Failed to trigger security alert: {str(e)}")
    
    async def get_audit_statistics(
        self,
        start_time: datetime,
        end_time: datetime
    ) -> Dict[str, Any]:
        """
        Get audit statistics for the specified time period
        
        Args:
            start_time: Statistics start time
            end_time: Statistics end time
            
        Returns:
            Audit statistics dictionary
        """
        try:
            events = await self.get_audit_events(
                start_time=start_time,
                end_time=end_time,
                limit=10000
            )
            
            stats = {
                "period": {
                    "start": start_time.isoformat(),
                    "end": end_time.isoformat()
                },
                "total_events": len(events),
                "events_by_type": {},
                "events_by_severity": {},
                "events_by_outcome": {},
                "average_risk_score": 0,
                "high_risk_events": 0,
                "unique_users": set(),
                "unique_ips": set()
            }
            
            total_risk_score = 0
            
            for event in events:
                event_type = event.get("event_type", "unknown")
                severity = event.get("severity", "low")
                outcome = event.get("outcome", "SUCCESS")
                risk_score = event.get("risk_score", 0)
                
                # Count by type
                stats["events_by_type"][event_type] = stats["events_by_type"].get(event_type, 0) + 1
                
                # Count by severity
                stats["events_by_severity"][severity] = stats["events_by_severity"].get(severity, 0) + 1
                
                # Count by outcome
                stats["events_by_outcome"][outcome] = stats["events_by_outcome"].get(outcome, 0) + 1
                
                # Risk score calculation
                total_risk_score += risk_score
                if risk_score >= 70:
                    stats["high_risk_events"] += 1
                
                # Track unique users and IPs
                if event.get("user_id"):
                    stats["unique_users"].add(event["user_id"])
                if event.get("ip_address"):
                    stats["unique_ips"].add(event["ip_address"])
            
            # Calculate averages
            if events:
                stats["average_risk_score"] = total_risk_score / len(events)
            
            # Convert sets to counts
            stats["unique_users"] = len(stats["unique_users"])
            stats["unique_ips"] = len(stats["unique_ips"])
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get audit statistics: {str(e)}")
            return {"error": str(e)}

# Global audit logging service instance
audit_logging_service = AuditLoggingService()

async def get_audit_logging_service() -> AuditLoggingService:
    """Get audit logging service instance"""
    return audit_logging_service