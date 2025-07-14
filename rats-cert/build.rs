#[cfg(feature = "attester-coco")]
use ttrpc_codegen::{Codegen, Customize, ProtobufCustomize};

fn main() {
    #[cfg(feature = "attester-coco")]
    {
        // Build for connecting AA with ttrpc
        let protos = vec!["src/tee/coco/protos/attestation-agent.proto"];
        let protobuf_customized = ProtobufCustomize::default().gen_mod_rs(false);

        Codegen::new()
            .out_dir("src/tee/coco/ttrpc_protocol")
            .inputs(&protos)
            .include("src/tee/coco/protos")
            .rust_protobuf()
            .customize(Customize {
                async_all: false, // TODO: enable async when async feature of rats-rs is ready
                ..Default::default()
            })
            .rust_protobuf_customize(protobuf_customized)
            .run()
            .expect("Generate ttrpc protocol code failed.");
    }

    #[cfg(feature = "verifier-coco")]
    {
        // Build for connecting AS with Grpc
        tonic_build::compile_protos("src/tee/coco/protos/attestation-service.proto")
            .expect("Generate grpc protocol code failed.");
    }
}
