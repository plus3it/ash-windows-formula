Contents of this directory created by using the `LGPO.EXE` utility's `-b` option to export the files:

* GptTmpl.inf
* audit.csv
* machine_registry.pol
* user_registry.pol

The above export was created using an EC2 launched from the officicial "[CIS Microsoft Windows Server 2016 Benchmark v1.3.0.2 - Level 2](https://aws.amazon.com/marketplace/pp/prodview-zgh6fzj3hbf7o?ref_=srh_res_product_title)" AMI (`ami-047a5a925b6b2b2be` in the us-east-1 AWS Commercial region).

The `.inf` and `.pol` files were converted to:

* gpttmpl.yml
* machine_registry.yml
* user_registry.yml

Per the guidance in the [Convert SCT Policies](../../../ash-windows/Convert_SCT_Policies.md) document.
Initial, exported CIS content
