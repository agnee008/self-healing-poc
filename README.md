Automatically responds to CloudWatch alarms with appropriate fixes:
- DynamoDB throttling → increase capacity
- Lambda timeouts → increase memory/timeout
- API Gateway errors → restart backends
- RDS connection issues → kill queries

Deploy as Lambda triggered by SNS from CloudWatch alarms.
