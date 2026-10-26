import time
import secrets
import threading
from typing import Callable, Any, Dict, Tuple, Optional
import grpc

HPACK_DYNAMIC_TABLE_BUDGET = 4096
HYSTERESIS_PADDING = 512
DEFAULT_HANDLE_TTL = 3600  

class DAFBSecurityContext:
    @staticmethod
    def calculate_wire_size(metadata_key: str, token: str) -> int:
        return len(metadata_key.encode('utf-8')) + len(token.encode('utf-8')) + 32

class ModifiedClientCallDetails:
    """Lightweight wrapper object to safely bypass grpc.ClientCallDetails immutability constraints."""
    def __init__(self, method, timeout, metadata, credentials, wait_for_ready):
        self.method = method
        self.timeout = timeout
        self.metadata = metadata
        self.credentials = credentials
        self.wait_for_ready = wait_for_ready

class DAFBClientInterceptor(grpc.UnaryUnaryClientInterceptor):
    def __init__(self, target_endpoint: str, metadata_auth_key: str = "authorization-pq"):
        self.target_endpoint = target_endpoint
        self.auth_key = metadata_auth_key
        self.handle_cache: Dict[str, Tuple[str, float]] = {}  
        self.cache_lock = threading.Lock()

    def intercept_unary_unary(
        self,
        continuation: Callable[[Any, Any], Any],
        client_call_details: Any,
        request: Any
    ) -> Any:
        metadata = list(client_call_details.metadata or [])
        raw_token: Optional[str] = None
        token_index: int = -1
        
        for idx, (key, val) in enumerate(metadata):
            if key == self.auth_key:
                raw_token = val
                token_index = idx
                break
                
        if not raw_token:
            return continuation(client_call_details, request)

        wire_footprint = DAFBSecurityContext.calculate_wire_size(self.auth_key, raw_token)
        hpack_threshold = HPACK_DYNAMIC_TABLE_BUDGET - HYSTERESIS_PADDING
        
        # Mutate structural metadata: Append our tracking flag directly to the list configuration
        if wire_footprint > hpack_threshold:
            metadata.append(("x-dafb-mode", "fallback-inline"))
        else:
            metadata.append(("x-dafb-mode", "inline"))

        updated_details = ModifiedClientCallDetails(
            client_call_details.method,
            client_call_details.timeout,
            metadata,
            client_call_details.credentials,
            client_call_details.wait_for_ready
        )

        return continuation(updated_details, request)

class DAFBServerInterceptor(grpc.ServerInterceptor):
    def __init__(self, metadata_auth_key: str = "authorization-pq"):
        self.auth_key = metadata_auth_key
        self.validation_cache: Dict[str, Dict[str, Any]] = {}
        self.cache_lock = threading.Lock()

    def register_incoming_handle(self, handle: str, validated_claims: Dict[str, Any]) -> None:
        with self.cache_lock:
            self.validation_cache[handle] = validated_claims

    def intercept_service(
        self,
        continuation: Callable[[grpc.HandlerCallDetails], grpc.RpcMethodHandler],
        handler_call_details: grpc.HandlerCallDetails
    ) -> grpc.RpcMethodHandler:
        return continuation(handler_call_details)
