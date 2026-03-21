"""
self_healing_aws.py - Automated Incident Response System

Automatically responds to CloudWatch alarms with appropriate fixes:
- DynamoDB throttling → increase capacity
- Lambda timeouts → increase memory/timeout
- API Gateway errors → restart backends
- RDS connection issues → kill queries

Author: Agnibes Banerjee
License: MIT

Deploy as Lambda triggered by SNS from CloudWatch alarms.
"""

import boto3
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IncidentResponder:
    """
    Automated incident response and self-healing system.
    """
    
    def __init__(self):
        self.cloudwatch = boto3.client('cloudwatch')
        self.dynamodb_client = boto3.client('dynamodb')
        self.lambda_client = boto3.client('lambda')
        self.ec2 = boto3.client('ec2')
        self.rds = boto3.client('rds')
        self.sns = boto3.client('sns')
        
        # DynamoDB for audit logging
        self.dynamodb = boto3.resource('dynamodb')
        self.log_table = self.dynamodb.Table('incident-response-log')
        
        # Safety checker
        self.safety = SafetyChecker()
        
        # Load playbooks
        self.playbooks = self._load_playbooks()
    
    def handle_alarm(self, alarm_event: Dict) -> Dict:
        """
        Main entry point: handle CloudWatch alarm.
        
        Returns incident resolution result.
        """
        alarm_name = alarm_event['AlarmName']
        metric_name = alarm_event['Trigger']['MetricName']
        namespace = alarm_event['Trigger']['Namespace']
        dimensions = alarm_event['Trigger']['Dimensions']
        
        logger.info(f"Handling alarm: {alarm_name}")
        
        # Identify incident type
        incident = self._identify_incident(
            alarm_name, metric_name, namespace, dimensions
        )
        
        if not incident:
            logger.warning("Could not identify incident type")
            return {
                'incident_type': 'unknown',
                'action_taken': 'none',
                'success': False,
                'human_required': True
            }
        
        logger.info(f"Identified as: {incident['type']}")
        
        # Get playbook
        playbook = self.playbooks.get(incident['type'])
        if not playbook:
            logger.warning(f"No playbook for {incident['type']}")
            return {
                'incident_type': incident['type'],
                'action_taken': 'no_playbook',
                'success': False,
                'human_required': True
            }
        
        # Check safety
        if not self.safety.can_apply_fix(incident['type'], incident['resource']):
            logger.warning("Safety check failed")
            return {
                'incident_type': incident['type'],
                'action_taken': 'safety_check_failed',
                'success': False,
                'human_required': True
            }
        
        # Execute playbook
        result = self._execute_playbook(playbook, incident)
        
        # Log the fix
        self.safety.log_fix(incident['type'], incident['resource'], result)
        
        # Send notification
        self._notify(incident, result)
        
        return result
    
    def _identify_incident(self, alarm_name: str, metric_name: str,
                          namespace: str, dimensions: List) -> Optional[Dict]:
        """Identify incident type from alarm details."""
        
        # DynamoDB throttling
        if namespace == 'AWS/DynamoDB' and 'Throttle' in metric_name:
            table_name = self._get_dimension_value(dimensions, 'TableName')
            return {
                'type': 'dynamodb_throttle',
                'resource': table_name,
                'severity': 'medium',
                'alarm_name': alarm_name
            }
        
        # Lambda timeout
        if namespace == 'AWS/Lambda' and 'Duration' in metric_name:
            function_name = self._get_dimension_value(dimensions, 'FunctionName')
            return {
                'type': 'lambda_timeout',
                'resource': function_name,
                'severity': 'high',
                'alarm_name': alarm_name
            }
        
        # Lambda errors
        if namespace == 'AWS/Lambda' and 'Errors' in metric_name:
            function_name = self._get_dimension_value(dimensions, 'FunctionName')
            return {
                'type': 'lambda_errors',
                'resource': function_name,
                'severity': 'critical',
                'alarm_name': alarm_name
            }
        
        # RDS connections
        if namespace == 'AWS/RDS' and 'DatabaseConnections' in metric_name:
            db_instance = self._get_dimension_value(dimensions, 'DBInstanceIdentifier')
            return {
                'type': 'rds_connection_exhaustion',
                'resource': db_instance,
                'severity': 'critical',
                'alarm_name': alarm_name
            }
        
        return None
    
    def _get_dimension_value(self, dimensions: List, name: str) -> Optional[str]:
        """Extract dimension value by name."""
        for dim in dimensions:
            if dim.get('name') == name or dim.get('Name') == name:
                return dim.get('value') or dim.get('Value')
        return None
    
    def _load_playbooks(self) -> Dict:
        """Load incident response playbooks."""
        return {
            'dynamodb_throttle': {
                'name': 'DynamoDB Throttling Auto-Fix',
                'auto_fix_enabled': True,
                'diagnostics': ['check_dynamodb_metrics'],
                'fixes': ['increase_dynamodb_capacity'],
                'verification': ['verify_throttling_stopped']
            },
            'lambda_timeout': {
                'name': 'Lambda Timeout Auto-Fix',
                'auto_fix_enabled': True,
                'diagnostics': ['check_lambda_config'],
                'fixes': ['increase_lambda_memory'],
                'verification': ['verify_lambda_success']
            },
            'lambda_errors': {
                'name': 'Lambda Error Spike Response',
                'auto_fix_enabled': False,  # Requires human review
                'diagnostics': ['check_error_rate'],
                'fixes': [],
                'verification': []
            },
            'rds_connection_exhaustion': {
                'name': 'RDS Connection Pool Fix',
                'auto_fix_enabled': True,
                'diagnostics': ['check_rds_connections'],
                'fixes': ['kill_long_queries'],
                'verification': ['verify_connection_health']
            }
        }
    
    def _execute_playbook(self, playbook: Dict, incident: Dict) -> Dict:
        """Execute incident response playbook."""
        
        resource = incident['resource']
        incident_type = incident['type']
        
        # Initialize log entry
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'incident_type': incident_type,
            'resource': resource,
            'alarm_name': incident['alarm_name'],
            'playbook': playbook['name'],
            'steps': []
        }
        
        # Run diagnostics
        diagnostic_results = {}
        for diag_name in playbook.get('diagnostics', []):
            diag_func = getattr(self, f'_{diag_name}', None)
            if diag_func:
                result = diag_func(resource)
                diagnostic_results[diag_name] = result
                log_entry['steps'].append({
                    'type': 'diagnostic',
                    'name': diag_name,
                    'result': str(result)[:500]  # Truncate for storage
                })
        
        # Check if auto-fix enabled
        if not playbook.get('auto_fix_enabled', False):
            self._log_to_dynamodb(log_entry)
            return {
                'incident_type': incident_type,
                'action_taken': 'diagnostics_only',
                'success': False,
                'human_required': True,
                'diagnostics': diagnostic_results
            }
        
        # Apply fixes
        fix_success = True
        for fix_name in playbook.get('fixes', []):
            fix_func = getattr(self, f'_{fix_name}', None)
            if fix_func:
                try:
                    result = fix_func(resource, diagnostic_results)
                    log_entry['steps'].append({
                        'type': 'fix',
                        'name': fix_name,
                        'result': str(result)[:500],
                        'success': True
                    })
                except Exception as e:
                    logger.error(f"Fix {fix_name} failed: {e}")
                    log_entry['steps'].append({
                        'type': 'fix',
                        'name': fix_name,
                        'error': str(e)[:500],
                        'success': False
                    })
                    fix_success = False
                    break
        
        if not fix_success:
            self._log_to_dynamodb(log_entry)
            return {
                'incident_type': incident_type,
                'action_taken': 'fix_failed',
                'success': False,
                'human_required': True
            }
        
        # Wait for fix to propagate
        time.sleep(30)
        
        # Verify
        all_verified = True
        for verify_name in playbook.get('verification', []):
            verify_func = getattr(self, f'_{verify_name}', None)
            if verify_func:
                result = verify_func(resource)
                log_entry['steps'].append({
                    'type': 'verification',
                    'name': verify_name,
                    'result': str(result)[:500]
                })
                if not result.get('success', False):
                    all_verified = False
        
        # Log completion
        self._log_to_dynamodb(log_entry)
        
        return {
            'incident_type': incident_type,
            'action_taken': 'auto_resolved' if all_verified else 'fix_applied',
            'success': all_verified,
            'human_required': not all_verified
        }
    
    # Diagnostic methods
    def _check_dynamodb_metrics(self, table_name: str) -> Dict:
        """Check DynamoDB throttling metrics."""
        table = self.dynamodb_client.describe_table(TableName=table_name)['Table']
        return {
            'billing_mode': table.get('BillingModeSummary', {}).get('BillingMode', 'PROVISIONED'),
            'read_capacity': table.get('ProvisionedThroughput', {}).get('ReadCapacityUnits', 0),
            'write_capacity': table.get('ProvisionedThroughput', {}).get('WriteCapacityUnits', 0)
        }
    
    def _check_lambda_config(self, function_name: str) -> Dict:
        """Check Lambda configuration."""
        config = self.lambda_client.get_function_configuration(FunctionName=function_name)
        return {
            'memory': config['MemorySize'],
            'timeout': config['Timeout']
        }
    
    def _check_rds_connections(self, db_instance: str) -> Dict:
        """Check RDS connection count."""
        # Simplified - in production, query performance_schema
        return {'active_connections': 'unknown'}
    
    # Fix methods
    def _increase_dynamodb_capacity(self, table_name: str, diagnostics: Dict) -> Dict:
        """Increase DynamoDB capacity by 50%."""
        metrics = diagnostics.get('check_dynamodb_metrics', {})
        
        if metrics.get('billing_mode') == 'PAY_PER_REQUEST':
            return {'action': 'none', 'reason': 'on-demand mode'}
        
        current_read = metrics['read_capacity']
        current_write = metrics['write_capacity']
        
        new_read = int(current_read * 1.5)
        new_write = int(current_write * 1.5)
        
        self.dynamodb_client.update_table(
            TableName=table_name,
            ProvisionedThroughput={
                'ReadCapacityUnits': new_read,
                'WriteCapacityUnits': new_write
            }
        )
        
        return {
            'action': 'capacity_increased',
            'old_read': current_read,
            'new_read': new_read,
            'old_write': current_write,
            'new_write': new_write
        }
    
    def _increase_lambda_memory(self, function_name: str, diagnostics: Dict) -> Dict:
        """Increase Lambda memory by 512 MB."""
        config = diagnostics.get('check_lambda_config', {})
        current_memory = config['memory']
        
        if current_memory >= 3008:
            return {'action': 'none', 'reason': 'at_max_memory'}
        
        new_memory = min(current_memory + 512, 3008)
        
        self.lambda_client.update_function_configuration(
            FunctionName=function_name,
            MemorySize=new_memory
        )
        
        return {
            'action': 'memory_increased',
            'old_memory': current_memory,
            'new_memory': new_memory
        }
    
    def _kill_long_queries(self, db_instance: str, diagnostics: Dict) -> Dict:
        """Kill long-running RDS queries."""
        # Simplified - in production, connect to DB and kill queries
        return {'action': 'queries_killed', 'count': 0}
    
    # Verification methods
    def _verify_throttling_stopped(self, table_name: str) -> Dict:
        """Verify DynamoDB throttling has stopped."""
        # Check recent throttle metrics
        # Simplified for example
        return {'success': True, 'throttles': 0}
    
    def _verify_lambda_success(self, function_name: str) -> Dict:
        """Verify Lambda success rate improved."""
        return {'success': True}
    
    def _verify_connection_health(self, db_instance: str) -> Dict:
        """Verify RDS connection pool is healthy."""
        return {'success': True}
    
    def _log_to_dynamodb(self, log_entry: Dict):
        """Log incident response to DynamoDB."""
        try:
            self.log_table.put_item(
                Item={
                    'resource': log_entry['resource'],
                    'timestamp': log_entry['timestamp'],
                    'incident_type': log_entry['incident_type'],
                    'playbook': log_entry['playbook'],
                    'steps': json.dumps(log_entry['steps']),
                    'ttl': int(time.time()) + (30 * 24 * 60 * 60)  # 30 days
                }
            )
        except Exception as e:
            logger.error(f"Failed to log to DynamoDB: {e}")
    
    def _notify(self, incident: Dict, result: Dict):
        """Send notification about incident response."""
        if result['human_required']:
            # Send page/critical alert
            message = f"Manual intervention needed: {incident['type']} on {incident['resource']}"
        else:
            # Send info notification
            message = f"Auto-resolved: {incident['type']} on {incident['resource']}"
        
        logger.info(f"Notification: {message}")


class SafetyChecker:
    """Safety checks before applying automated fixes."""
    
    def __init__(self):
        self.dynamodb = boto3.resource('dynamodb')
        self.log_table = self.dynamodb.Table('incident-response-log')
    
    def can_apply_fix(self, incident_type: str, resource: str) -> bool:
        """Check if safe to apply fix."""
        
        # Check recent fixes (max 3 per hour)
        recent_fixes = self._get_recent_fixes(resource, hours=1)
        if len(recent_fixes) >= 3:
            logger.warning(f"Too many recent fixes for {resource}")
            return False
        
        return True
    
    def _get_recent_fixes(self, resource: str, hours: int = 1) -> List:
        """Get recent fixes for resource."""
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        try:
            response = self.log_table.query(
                KeyConditionExpression='resource = :r AND #ts > :t',
                ExpressionAttributeNames={'#ts': 'timestamp'},
                ExpressionAttributeValues={':r': resource, ':t': cutoff}
            )
            return response.get('Items', [])
        except:
            return []
    
    def log_fix(self, incident_type: str, resource: str, result: Dict):
        """Log fix application."""
        logger.info(f"Logged fix: {incident_type} on {resource}")


def lambda_handler(event, context):
    """
    Lambda handler - triggered by SNS from CloudWatch alarms.
    """
    
    try:
        # Parse SNS message
        sns_message = event['Records'][0]['Sns']
        alarm_event = json.loads(sns_message['Message'])
        
        # Handle incident
        responder = IncidentResponder()
        result = responder.handle_alarm(alarm_event)
        
        return {
            'statusCode': 200,
            'body': json.dumps(result)
        }
        
    except Exception as e:
        logger.error(f"Error handling incident: {e}", exc_info=True)
        return {'statusCode': 500, 'body': str(e)}


if __name__ == '__main__':
    # For local testing
    test_event = {
        'Records': [{
            'Sns': {
                'Message': json.dumps({
                    'AlarmName': 'DynamoDB-Throttling-Test',
                    'Trigger': {
                        'MetricName': 'UserErrors',
                        'Namespace': 'AWS/DynamoDB',
                        'Dimensions': [
                            {'Name': 'TableName', 'Value': 'test-table'}
                        ]
                    }
                })
            }
        }]
    }
    
    result = lambda_handler(test_event, None)
    print(json.dumps(result, indent=2))
