import grpc
import sys
from protobufs import security_service_pb2 as pb2
from protobufs import security_service_pb2_grpc as pb2_grpc
from interceptors.dafb_engine import DAFBClientInterceptor

def run_experiment(simulate_pq_overhead: bool):
    target = "localhost:50051"
    client_interceptor = DAFBClientInterceptor(target_endpoint=target)
    
    raw_channel = grpc.insecure_channel(target, options=[
        ('grpc.max_metadata_size', 32768),
        ('grpc.http2.max_frame_size', 16384)
    ])
    
    channel = grpc.intercept_channel(raw_channel, client_interceptor)
    stub = pb2_grpc.CredentialBrokerStub(channel)
    
    if simulate_pq_overhead:
        token_payload = "X" * 5120
        print("🧪 Scenario: Running with heavy 5KB Post-Quantum Signature Token...")
    else:
        token_payload = "X" * 256
        print("🧪 Scenario: Running with standard 256-byte Classical Token...")
        
    request = pb2.RegistrationRequest(raw_token="baseline_telemetry_probe")
    metadata_packet = [("authorization-pq", token_payload)]
    
    try:
        response, call = stub.RegisterCredential.with_call(
            request, 
            metadata=metadata_packet,
            timeout=5.0
        )
        print("\n--- Telemetry Metrics ---")
        print(f"Status: Success")
        print(f"Assigned Opaque Pointer Handle: {response.opaque_handle}")
    except grpc.RpcError as e:
        print(f"❌ Execution Fault Observed: {e.code()} - {e.details()}", file=sys.stderr)

if __name__ == '__main__':
    run_experiment(simulate_pq_overhead=True)
