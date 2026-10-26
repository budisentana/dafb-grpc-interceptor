import time
from concurrent import futures
import grpc
import sys

from protobufs import security_service_pb2 as pb2
from protobufs import security_service_pb2_grpc as pb2_grpc
from interceptors.dafb_engine import DAFBServerInterceptor

class CredentialBrokerServicer(pb2_grpc.CredentialBrokerServicer):
    def __init__(self, interceptor_instance):
        self.interceptor = interceptor_instance

    def RegisterCredential(self, request, context):
        import secrets
        opaque_handle = f"dafb_ref_{secrets.token_hex(16)}"
        simulated_claims = {
            "sub": "i_wayan_budi_sentana",
            "role": "research_experimenter"
        }
        self.interceptor.register_incoming_handle(opaque_handle, simulated_claims)
        return pb2.RegistrationResponse(
            opaque_handle=opaque_handle,
            expires_at=int(time.time()) + 3600
        )

def serve():
    server_interceptor = DAFBServerInterceptor()
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=10),
        interceptors=(server_interceptor,),
        options=[
            ('grpc.max_metadata_size', 32768),
            ('grpc.http2.max_frame_size', 16384)
        ]
    )
    servicer = CredentialBrokerServicer(server_interceptor)
    pb2_grpc.add_CredentialBrokerServicer_to_server(servicer, server)
    server.add_insecure_port('[::]:50051')
    print("🚀 DAFB Secure gRPC Production Server initialized on port 50051...")
    
    try:
        server.start()
        while True:
            time.sleep(86400)
    except KeyboardInterrupt:
        server.stop(0)

if __name__ == '__main__':
    serve()
