NORMALIZED_SEED_TEMPLATE = {
    "event_id": None,
    "event_time": None,
    "ingest_time": None,

    "detection": {
        "detection_id": None,
        "name": None,
        "severity": None,
        "security_domain": None,
        "category": None,
        "type": None,
        "source": None
    },

    "source_context": {
        "siem": None,
        "index": None,
        "sourcetype": None,
        "source": None,
        "host": None
    },

    "entities": {
        "host": None,
        "hostname": None,
        "device_id": None,
        "asset_id": None,
        "user": None,
        "user_id": None,
        "account_name": None,
        "account_domain": None,
        "src_ip": None,
        "src_host": None,
        "src_port": None,
        "dest_ip": None,
        "dest_host": None,
        "dest_port": None
    },

    "authentication": {
        "action": None,
        "status": None,
        "authentication_method": None,
        "logon_type": None,
        "failure_reason": None,
        "session_id": None,
        "source_user": None,
        "target_user": None
    },

    "process": {
        "process_name": None,
        "process_path": None,
        "process_id": None,
        "process_guid": None,
        "command_line": None,
        "parent_process_name": None,
        "parent_process_path": None,
        "parent_process_id": None,
        "parent_command_line": None,
        "child_process_name": None,
        "child_process_id": None
    },

    "file": {
        "file_name": None,
        "file_path": None,
        "file_extension": None,
        "file_size": None,
        "md5": None,
        "sha1": None,
        "sha256": None,
        "file_action": None,
        "file_owner": None,
        "file_signature": None
    },

    "registry": {
        "registry_path": None,
        "registry_key": None,
        "registry_value_name": None,
        "registry_value_data": None,
        "registry_action": None
    },

    "network": {
        "src_ip": None,
        "src_port": None,
        "dest_ip": None,
        "dest_port": None,
        "protocol": None,
        "transport_protocol": None,
        "application_protocol": None,
        "direction": None,
        "action": None,
        "bytes_in": None,
        "bytes_out": None,
        "bytes_total": None,
        "packets_in": None,
        "packets_out": None,
        "connection_count": None
    },

    "dns": {
        "query": None,
        "query_type": None,
        "query_length": None,
        "response": None,
        "response_code": None,
        "record_type": None,
        "resolved_ip": None
    },

    "http": {
        "url": None,
        "uri": None,
        "domain": None,
        "hostname": None,
        "http_method": None,
        "status_code": None,
        "user_agent": None,
        "referrer": None,
        "request_size": None,
        "response_size": None,
        "content_type": None
    },

    "email": {
        "sender": None,
        "recipient": None,
        "cc": [],
        "subject": None,
        "message_id": None,
        "attachment_names": [],
        "attachment_hashes": [],
        "urls": [],
        "domains": []
    },

    "threat_observables": {
        "ip_addresses": [],
        "domains": [],
        "urls": [],
        "file_hashes": [],
        "email_addresses": [],
        "file_names": []
    },

    "endpoint": {
        "device_name": None,
        "device_id": None,
        "os": None,
        "os_version": None,
        "agent_id": None,
        "agent_version": None,
        "action": None,
        "status": None
    },

    "cloud": {
        "cloud_provider": None,
        "account_id": None,
        "subscription_id": None,
        "tenant_id": None,
        "region": None,
        "resource_id": None,
        "resource_type": None,
        "resource_name": None,
        "service": None,
        "operation": None
    },

    "identity": {
        "user": None,
        "user_id": None,
        "user_type": None,
        "role": None,
        "privilege": None,
        "source_identity": None,
        "target_identity": None
    },

    "geo": {
        "src_country": None,
        "src_city": None,
        "dest_country": None,
        "dest_city": None,
        "latitude": None,
        "longitude": None
    },

    "event": {
        "event_code": None,
        "event_type": None,
        "event_category": None,
        "event_action": None,
        "event_status": None,
        "message": None
    },

    "tags": [],
    "additional_fields": {},
    "raw_event": None
}
