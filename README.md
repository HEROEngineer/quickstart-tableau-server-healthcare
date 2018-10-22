# quickstart-tableau-server-healthcare
## Tableau Server for Healthcare on the AWS Cloud

**Important note** You must have an AWS Business Associate Addendum (BAA) in place, and follow its configuration requirements, before running protected health information (PHI) workloads on AWS. For details, see the ![deployment guide](https://fwd.aws/bBJnv).

This Quick Start helps you deploy a Tableau Server standalone environment on the AWS Cloud, following best practices from AWS and Tableau Software. Specifically, this environment can help organizations with workloads that fall within the scope of the U.S. Health Insurance Portability and Accountability Act (HIPAA). The Quick Start addresses certain technical requirements in the Privacy, Security, and Breach Notification Rules under the HIPAA Administrative Simplification Regulations (45 C.F.R. Parts 160 and 164). 

The Quick Start includes AWS CloudFormation templates, which automatically configure the Tableau Server environment in less than an hour. The ![security controls reference](https://fwd.aws/YYYmx) (Microsoft Excel spreadsheet) shows how Quick Start architecture decisions, components, and configurations map to HIPAA regulatory requirements. The Quick Start also includes a ![deployment guide](https://fwd.aws/bBJnv), which describes the reference architecture in detail and provides step-by-step instructions for deploying, configuring, and validating the AWS environment.

The Quick Start offers two deployment options:

- Deploying Tableau Server for healthcare into a new virtual private cloud (VPC) on AWS
- Deploying Tableau Server for healthcare into an existing VPC on AWS

You can also use the AWS CloudFormation templates as a starting point for your own implementation.

![Quick Start architecture for Tableau Server for healthcare on AWS](https://d0.awsstatic.com/partner-network/QuickStart/datasheets/tableau-server-healthcare-architecture-on-aws.png)


To post feedback, submit feature ideas, or report bugs, use the **Issues** section of this GitHub repo.
If you'd like to submit code for this Quick Start, please review the [AWS Quick Start Contributor's Kit](https://aws-quickstart.github.io/). 
