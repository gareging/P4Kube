# P4Kube: In-Network Load-Aware Load Balancer for Kubernetes

> **P4Kube: In-Network Load Balancer for Kubernetes**  
> [Read the conference paper here](https://scholar.google.com/citations?view_op=view_citation&hl=en&user=D8zUvAMAAAAJ&sortby=pubdate&citation_for_view=D8zUvAMAAAAJ:3fE2CSJIrl8C)

## Citation

If you use **P4Kube** in your research, please cite our paper:

```@inproceedings{grigoryan2025p4kube,
title={P4Kube: In-Network Load Balancer for Kubernetes},
author={Grigoryan, Garegin and Penkowski, Kevin and Kwon, Minseok},
booktitle={2025 IEEE 22nd Consumer Communications & Networking Conference (CCNC)},
pages={1--6},
year={2025},
organization={IEEE}
}
```
---

## Getting Started

To run the code and reproduce our experiments:

1. **Access the FABRIC testbed**  
   Ensure you have a FABRIC account and access to [JupyterLab on FABRIC](https://learn.fabric-testbed.net/).

2. **Clone the repository inside JupyterLab on FABRIC:**
   ```bash
   git clone https://github.com/gareging/P4Kube.git
   cd P4Kube

## Launch the Notebook

Open `P4Kube.ipynb` in JupyterLab on the FABRIC testbed and follow the step-by-step cells to 
- reserve the slice,
- setup and configure networking using bmv2 P4 switch emulator,
- setup and configure the Kubernetes cluster.

For any questions, email to grigoryan@alfred.edu.

## Testing QUIC

On master, run 

   ```
   kubectl apply -f quic.yaml
   ```

On the client:

   ```
   sudo apt install libssl-dev python3.9 python3.9-venv python3.9-dev -y;
   sudo apt install python3-pip -y;
   pip3 install aioquic wsproto;
   git clone https://github.com/aiortc/aioquic.git;
   cd aioquic/examples;
   python3 http3_client.py --insecure https://<vip_of_quic_deployment>:4433/;
   ```

