pub mod attachment;
pub mod buyer;
pub mod employee;
pub mod product;

pub use attachment::{
    AttachmentFullResponse, AttachmentMetaResponse, AttachmentV1, UploadAttachmentDto,
};
pub use buyer::{BuyerV1, BuyerDto, BuyerResponse};
pub use employee::{EmployeeV1, EmployeeDto, EmployeeResponse};
pub use product::{
    ProductV1, ProductV2, ProductV1Dto, ProductV1Response, ProductV2Response, RetailV1ToV2Decoder,
};

pub mod seed_counts {
    pub const PRODUCTS: usize = 5;
    pub const BUYERS: usize = 3;
    pub const EMPLOYEES: usize = 2;
    pub const MIN_PRODUCT_HISTORY: usize = 3;
    pub const ATTACHMENT_BYTES: usize = 2 * 1024 * 1024;
}
