### ReactJS: Youtube app Deployed on EKS using Github, terraform, jenkins, sonar, trivy, kubernetes.
<ul>
<li>Image</li>
<li>Tools &amp; Services used</li>
<li><details><summary>Clone Repository</summary>
<ul>
<li>$glt clone&nbsp;<a href="https://github.com/AbdulAziz-uk/youtube.git">https://github.com/AbdulAziz-uk/youtube.git</a>&nbsp;</li>
<li>youtube3</li>
</ul>
</details></li>
<li>Project Architecure:</li>
<li><details><summary>Deploy locally:</summary>
<ul>
<li>Clone the repository:&nbsp; $glt clone&nbsp;<a href="https://github.com/AbdulAziz-uk/youtube.git">https://github.com/AbdulAziz-uk/youtube.git</a>&nbsp;</li>
<li>change directory: $cd youtube</li>
<li>Install JDK17:&nbsp;</li>
<li>Install npm:&nbsp;</li>
<li>$npm install</li>
<li>$npm run start</li>
<li>access:http://localhost or ip:3000</li>
</ul>
</details></li>
<li><details><summary>Infra Setup for CI/CD:</summary>
<ul>
<li>youtube1&nbsp;</li>
<li>Create a VM to deploy jenkins server using terraform on AWS</li>
<li>Install AWS CLI</li>
<li>Install Terraform</li>
<li>Install VS code</li>
<li>open vscode and create the following files, which will create jenkins sonarqube and trivy with script
<ul>
<li>main.tf</li>
<li>provider.tf</li>
<li>tools.sh</li>
</ul>
</li>
<li>Access Jenkins:</li>
<li>Jenkins Plugins:
<ul>
<li>Eclipse Temurin</li>
<li>Stage View</li>
<li>Sonarqube scanner</li>
<li>sonar quality gate</li>
<li>quality gate</li>
<li>nodejs</li>
<li>docker</li>
<li>docker commons</li>
<li>docker pipeline</li>
<li>docker API</li>
<li>docker build step</li>
</ul>
</li>
<li>Jenkins tools:
<ul>
<li>jdk, name=jdk17, install automatically,&nbsp; install from adoptium.net, version 17.0.8.1+1</li>
<li>nodejs: name=node16, node js 16.2.0, install automatically, install from nodejs.org</li>
<li>docker installation: name = docker, automatically, install from docker.com, version = latest</li>
<li>sonarqube: add sonarqube scanner, name = sonar-scanner, install automatically, install from maven central</li>
</ul>
</li>
<li>Generate&nbsp; token &amp; webhook for jenkins, create project:
<ul>
<li>Go sonar qube server/administration/security/users/administration generate token, name=sonar-token, generate and copy token</li>
<li>Go sonar qube server /administration/configuration/webhook, name=jenkins, url=http://ip_of_jenkins:8080/sonarqube-webhook/&nbsp;</li>
<li>Go to sonarqube server/projects/manually/name=youtube CI/CD, project key=youtube CI/CD, main branch and click setup.&nbsp; click locally, token name =&nbsp;Analyze "youtube CI/CD" and generate, option =other, linux and generate.</li>
<li>sonar-scanner \<br /> -Dsonar.projectKey=youtube-CI-CD \<br /> -Dsonar.sources=. \<br /> -Dsonar.host.url=http://192.168.19.129:9000 \<br /> -Dsonar.login=sqp_525f6bd760a5570e750c32dc94a2ff22c9db3152</li>
<li>use this command in CI/CD sonarqube stage.</li>
</ul>
</li>
<li>Add Credentials&nbsp;
<ul>
<li>Go to Manage Jenkins/credentials, add credentilas/type = secret text, secret = paste token, ID=sonar-token, Description = sonar-token and click add</li>
</ul>
</li>
<li>Configure Sonar Qube Server&nbsp;
<ul>
<li>Got o Manage Jenkins/System/sonar qube server / add sonarqube/name=sonar, URL=http://ip:9000 (remove / after 9000), select credentials and save.</li>
</ul>
</li>
</ul>
</details></li>
<li><details><summary>Integrate Gmail with Jenkins for Email Notification for CICD pipeline progress:</summary>
<ul>
<li>Gmail Setup:
<ul>
<li>To receive emails for success/failure of CICD pipeline.</li>
<li>Go to Gmail account and click on account top right corner and select manage your account.</li>
<li>type app passwords (This option will only available after MFA is enabled, To enable go to security/2 step verification and enable it and add phone number)</li>
<li>app name=hotstar and create password.&nbsp; copy app password.</li>
</ul>
</li>
<li>Go to Manage Jenkins/System/E-mail Notification
<ul>
<li>SMTP Server = smtp.gmail.com</li>
<li>Default user email suffix=@gmail.com</li>
<li>Advanced</li>
<li>select Use SMTP Authentication:</li>
<li>user name = <a href="mailto:aziz.azure2024@gmail.com">aziz.azure2024@gmail.com</a>&nbsp;(enter email address for which app password has been created)</li>
<li>Password = xhce&nbsp;itbv&nbsp;erpf&nbsp;qedg (paste token)</li>
<li>select Use SSL</li>
<li>SMTP Port = 465 (open this port on firewall)</li>
<li>Reply-To-Address = <a href="mailto:aziz.azure2024@gmail.com">aziz.azure2024@gmail.com</a></li>
<li>Charset = UTF-8</li>
<li>Select Test configurtion by sending test e-mail</li>
<li>Test e-mail recipient = <a href="mailto:aziz.azure2024@gmail.com">aziz.azure2024@gmail.com</a></li>
<li>Test Configuration: Email received.</li>
</ul>
</li>
<li>Go to Manage Jenkins/System/Extended E-mail Notification
<ul>
<li>SMTP server=smtp.gmail.com</li>
<li>SMTP Port =587 (open port)</li>
<li>Advanced:</li>
<li>Credentials: Add Jenkins
<ul>
<li>Domain: global credentials (unrestricted)</li>
<li>Kind = Username with Password</li>
<li>Scope = Global (Jenkins, nodes, items, all child items,etc)</li>
<li>username = <a href="mailto:aziz.azure2024@gmail.com">aziz.azure2024@gmail.com</a></li>
<li>Password=xhce&nbsp;itbv&nbsp;erpf&nbsp;qedg (paste token)</li>
<li>ID = smtp-gmail</li>
<li>Description = smtp-gmail</li>
</ul>
</li>
<li>In credentials selet smtp-gmail</li>
<li>select Use TLS</li>
<li>Default user e-mail suffix = @gmail.com</li>
<li>Trigger = always, failure, success.</li>
<li>Apply &amp; Save</li>
</ul>
</li>
<li>Add code in Pipeline.
<ul>
<li>
<div>Make sure this code is inserted after completion of stages as this code is not starting with stage, steps.</div>
<div>post {<br /> always {<br /> emailext attachLog: true,<br /> subject: "'${currentBuild.result}'",<br /> body: "Project: ${env.JOB_NAME}&lt;br/&gt;" +<br /> "Build Number: ${env.BUILD_NUMBER}&lt;br/&gt;" +<br /> "URL: ${env.BUILD_URL}&lt;br/&gt;",<br /> to: 'aziz.azure2024@gmail.com', <br /> attachmentsPattern: 'trivyfs.txt,trivyimage.txt'<br /> }<br /> }</div>
</li>
</ul>
</li>
<li>Code</li>
</ul>
</details></li>
<li><details><summary>CI/CD Deploy on Container:</summary>
<ul>
<li>youtube2.jpg</li>
<li>Create new item, name=youtube, pipeline and create.</li>
<li>CI/CD.yml</li>
<li>Build</li>
<li>Access: http://ip:3100</li>
</ul>
</details></li>
<li><details><summary>CI/CD Deploy on Kubernetes:</summary>
<ul>
<li>Create AWS EKS Cluster with Terraform.</li>
<li>Click for Github repository: <a href="https://github.com/AbdulAziz-uk/EKS_with_Terraform.git" target="_blank" rel="noopener">EKS_with Terraform</a></li>
<li>Install AWS CLI:&nbsp; Create a VM or perform on your local computer:&nbsp;
<ul>
<li>on your laptop / local VM / AWS VM through we can configure EKS cluster on AWS</li>
<li>Get Security Credentials (AWS Security Key, Security Access Key) of a user from AWS(click on user top right corner on aws console and security credentials/ AWS command CLI/ and create keys)</li>
<li>ubuntu@ip-172-31-37-97:~$ sudo apt up</li>
<li>$curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"<br />sudo apt-get install unzip -y<br />unzip awscliv2.zip<br />sudo ./aws/install</li>
<li>$aws configure</li>
<li>Enter access key and secret access key, Region (eu-west-2)</li>
</ul>
</li>
<li>Clone Repository of EKS with Terraform:
<ul>
<li>$git clone&nbsp;<a href="https://github.com/AbdulAziz-uk/EKS_with_Terraform.git">https://github.com/AbdulAziz-uk/EKS_with_Terraform.git</a></li>
<li>$cd EKS_with_terraform:&nbsp; This folder contain</li>
<li>RBAC</li>
<li>main.tf: It contains all the codes to create VPC and EKS</li>
<li>output.tf:&nbsp; It outputs cluster id, nodegroup id, vpc id, subnet id.</li>
<li>variable.tf: It contains ssh key of AWS</li>
</ul>
</li>
<li>Install Terraform:
<ul>
<li>$sudo vim terraform.sh</li>
<li>paste the below script
<ul>
<li>
<p>#!/bin/bash<br /># Script to install Terraform on an instance</p>
<p># Update package list and install dependencies<br />sudo apt-get update &amp;&amp; sudo apt-get install -y gnupg software-properties-common</p>
<p># Add HashiCorp GPG key<br />wget -O- https://apt.releases.hashicorp.com/gpg | \<br />gpg --dearmor | \<br />sudo tee /usr/share/keyrings/hashicorp-archive-keyring.gpg &gt; /dev/null</p>
<p># Verify the key fingerprint<br />gpg --no-default-keyring \<br />--keyring /usr/share/keyrings/hashicorp-archive-keyring.gpg \<br />--fingerprint</p>
<p># Add HashiCorp repository to sources list<br />echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] \<br />https://apt.releases.hashicorp.com $(lsb_release -cs) main" | \<br />sudo tee /etc/apt/sources.list.d/hashicorp.list</p>
<p># Update package lists<br />sudo apt update</p>
<p># Install Terraform<br />sudo apt-get install terraform -y</p>
<p>## Verify installation<br />terraform -v</p>
</li>
</ul>
</li>
<li>make script executable</li>
<li>$sudo chmod +x terraform.sh</li>
<li>Run Script</li>
<li>$sudo sh terraform.sh (it will install terraform)</li>
<li>$terraform --version</li>
</ul>
</li>
<li>Configure EKS on AWS:
<ul>
<li>Initialize the terraform.</li>
<li>ubuntu@ip-172-31-37-97:~/EKS_with_Terraform$ terraform init</li>
<li>Run terraform plan:</li>
<li>ubuntu@ip-172-31-37-97:~/EKS_with_Terraform$ terraform plan</li>
<li>&nbsp;Run Terraform apply:</li>
<li>ubuntu@ip-172-31-37-97:~/EKS_with_Terraform$ terraform apply&nbsp; --auto-approve</li>
<li>It will create 19 resources:</li>
</ul>
</li>
<li>Configure Kubeconfig:&nbsp; We will be able to access the cluster.
<ul>
<li>ubuntu@ip-172-31-37-97:~/EKS_with_Terraform$aws&nbsp;eks --region eu-west-2 update-kubeconfig --name star-cluster</li>
<li>Added new context arn:aws:eks:eu-west-2:034646250868:cluster/star-cluster to /home/ubuntu/.kube/config</li>
</ul>
</li>
<li>Install kubectl:&nbsp; We can communicate with cluster and perform commands&nbsp;
<ul>
<li>ubuntu@ip-172-31-37-97:~/EKS_with_Terraform$curl -LO https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl<br />sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl<br />kubectl version --client</li>
</ul>
</li>
<li>Install eksctl:
<ul>
<li>ubuntu@ip-172-31-37-97:~/EKS_with_Terraform$curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp<br />sudo mv /tmp/eksctl /usr/local/bin<br />kubectl version --client</li>
</ul>
</li>
<li>Associate iam-oidc-provider:
<ul>
<li>ubuntu@ip-172-31-37-97:~$ eksctl utils associate-iam-oidc-provider --region eu-west-2 --cluster star-cluster --approve</li>
</ul>
</li>
<li>Create IAM Service Account for EBS CSI Driver:
<ul>
<li>ubuntu@ip-172-31-37-97:~$eksctl create iamserviceaccount \<br /> --region eu-west-2 \<br /> --name ebs-csi-controller-sa \<br /> --namespace kube-system \<br /> --cluster star-cluster \<br /> --attach-policy-arn arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy \<br /> --approve \<br /> --override-existing-serviceaccounts</li>
</ul>
</li>
<li>Deploy Add-Ons
<ul>
<li>EBS CSI Driver:</li>
<li>ubuntu@ip-172-31-37-97:~$kubectl apply -k "github.com/kubernetes-sigs/aws-ebs-csi-driver/deploy/kubernetes/overlays/stable/ecr/?ref=release-1.11"</li>
<li>NGINX Ingress Controller:</li>
<li>ubuntu@ip-172-31-37-97:~$kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/cloud/deploy.yaml</li>
<li>cert-manager:</li>
<li>ubuntu@ip-172-31-37-97:~$kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.12.0/cert-manager.yaml</li>
</ul>
</li>
</ul>
</details></li>
<li><details><summary>Infra Setup for Monitoring:</summary>
<ul>
<li>Create a T2.Micro VM, 15 GB storage,&nbsp;</li>
<li>Prometheus:
<ul>
<li>Create a system user &amp; group - prometheus:&nbsp;
<ul>
<li>sudo useradd \<br />--system \<br />--no-create-home \<br />--shell /bin/false prometheus</li>
<li>--system &ndash; Will create a system account.<br />--no-create-home &ndash; We don&rsquo;t need a home directory for Prometheus or any other system accounts in our case.<br />--shell /bin/false &ndash; It prevents logging in as a Prometheus user.</li>
<li>Will create a Prometheus user and a group with the same name.</li>
</ul>
</li>
<li>Download Prometheus:
<ul>
<li>wget <a href="https://github.com/prometheus/prometheus/releases/download/v2.47.1/prometheus-2.47.1.linux-amd64.tar.gz">https://github.com/prometheus/prometheus/releases/download/v2.47.1/prometheus-2.47.1.linux-amd64.tar.gz</a></li>
</ul>
</li>
<li>&nbsp;Extract tar.gz file:
<ul>
<li>$ tar -xvf prometheus-2.47.1.linux-amd64.tar.gz</li>
<li>list of files:</li>
<li>console_libraries LICENSE prometheus promtool<br />consoles NOTICE prometheus.yml</li>
</ul>
</li>
<li>Create a folder /data &amp; /etc/prometheus
<ul>
<li>Usually, you would have a disk mounted to the data directory.&nbsp; Simply create a /data directory. Also, you need a folder for Prometheus configuration files.</li>
<li>$sudo mkdir -p /data /etc/prometheus</li>
<li>Two folder will be created one at /data and another /etc/prometheus</li>
</ul>
</li>
<li>Change the directory to&nbsp;prometheus-2.47.1.linux-amd64 and move some files.&nbsp;
<ul>
<li>$cd prometheus-2.47.1.linux-amd64/</li>
<li>let&rsquo;s move the prometheus&nbsp; &amp; promtool to the /usr/local/bin/. promtool is used to check configuration files and Prometheus rules.&nbsp;</li>
<li>$sudo mv prometheus promtool /usr/local/bin/</li>
<li>Optionally, we can move console libraries to the prometheus configuration directory. Console templates allow for the creation of arbitrary consoles using the Go templating language. You don&rsquo;t need to worry about it if you&rsquo;re just getting started.&nbsp;</li>
<li>$sudo mv consoles/ console_libraries/ /etc/prometheus/</li>
<li>Finally, let&rsquo;s move the example of the main Prometheus configuration file.&nbsp;</li>
<li>$sudo mv prometheus.yml /etc/prometheus/prometheus.yml</li>
</ul>
</li>
<li>Set Permission:&nbsp; To avoid permission issues, set the ownership for the /etc/prometheus/ and /data directory.&nbsp;
<ul>
<li>$sudo chown -R prometheus:prometheus /etc/prometheus/ /data/</li>
</ul>
</li>
<li>Delete the archive and a prometheus folder when you are done.&nbsp;
<ul>
<li>$ rm -rf prometheus-2.47.1.linux-amd64.tar.gz</li>
</ul>
</li>
<li>Execute prometheus binary:&nbsp;Verify that prometheus binary can be execute by running the following command:&nbsp;
<ul>
<li>$prometheus --version</li>
<li>$prometheus --help (To get more information and configuration options, run Prometheus Help)</li>
</ul>
</li>
<li>Set systemd:&nbsp; We&rsquo;re going to use systemd, which is a system and service manager for Linux operating systems. For that, we need to create a systemd unit configuration file.&nbsp;
<ul>
<li>$sudo vim /etc/systemd/system/prometheus.service.</li>
<li>paste the following :</li>
<li>[Unit]<br />Description=Prometheus<br />Wants=network-online.target<br />After=network-online.target<br />StartLimitIntervalSec=500<br />StartLimitBurst=5<br />[Service]<br />User=prometheus<br />Group=prometheus<br />Type=simple<br />Restart=on-failure<br />RestartSec=5s<br />ExecStart=/usr/local/bin/prometheus \<br /> --config.file=/etc/prometheus/prometheus.yml \<br /> --storage.tsdb.path=/data \<br /> --web.console.templates=/etc/prometheus/consoles \<br /> --web.console.libraries=/etc/prometheus/console_libraries \<br /> --web.listen-address=0.0.0.0:9090 \<br /> --web.enable-lifecycle<br />[Install]<br />WantedBy=multi-user.target</li>
<li>info: Let&rsquo;s go over a few of the most important options related to systemd and prometheus. Restart &ndash; Configures whether the service shall be restarted when the service process exits, is killed, or a timeout is reached.<br />RestartSec &ndash; Configures the time to sleep before restarting a service.<br />User and Group &ndash; Are Linux user and a group to start a prometheus process.<br />&ndash;config.file=/etc/prometheus/prometheus.yml &ndash; Path to the main Prometheus configuration file.<br />&ndash;storage.tsdb.path=/data &ndash; Location to store Prometheus data.<br />&ndash;web.listen-address=0.0.0.0:9090 &ndash; Configure to listen on all network interfaces. In some situations, you may have a proxy such as nginx to redirect requests to Prometheus. In that case, you would configure Prometheus to listen only on&nbsp;<a href="http://localhost/" target="_blank" rel="noopener"><strong>localhost</strong></a>.<br />&ndash;web.enable-lifecycle &mdash; Allows to manage Prometheus, for example, to reload configuration without restarting the service.</li>
</ul>
</li>
<li>To automatically start the prometheus after reboot, run enable.&nbsp;
<ul>
<li>$sudo systemctl enable prometheus</li>
</ul>
</li>
<li>Start the prometheus.
<ul>
<li>$sudo systemctl start prometheus</li>
</ul>
</li>
<li>Ccheck the status of prometheus:&nbsp;
<ul>
<li>$sudo systemctl status prometheus</li>
</ul>
</li>
<li>Access prometheus:
<ul>
<li>open browser: <a href="http://public-ip:9090">http://public-ip:9090</a></li>
<li>youtube4</li>
<li>If you go to targets, you should see only one &ndash; Prometheus target. It scrapes itself every 15 seconds by default.</li>
</ul>
</li>
</ul>
</li>
<li>Install Node Exporter on Ubuntu 22.04
<ul>
<li>Set up and configure Node Exporter to collect Linux system metrics like CPU load and disk I/O. Node Exporter will expose these as Prometheus-style metrics. Since the installation process is very similar.</li>
<li>Create a system user for Node Exporter by running the following command:
<ul>
<li>sudo useradd \<br /> --system \<br /> --no-create-home \<br /> --shell /bin/false node_exporter</li>
</ul>
</li>
<li>Download Node Exporter:
<ul>
<li>$wget <a href="https://github.com/prometheus/node_exporter/releases/download/v1.6.1/node_exporter-1.6.1.linux-amd64.tar.gz">https://github.com/prometheus/node_exporter/releases/download/v1.6.1/node_exporter-1.6.1.linux-amd64.tar.gz</a></li>
</ul>
</li>
<li>Extract the node exporter from the archive.&nbsp;
<ul>
<li>$tar -xvf node_exporter-1.6.1.linux-amd64.tar.gz</li>
<li>$cd&nbsp;node_exporter-1.6.1.linux-amd64</li>
<li>$ls</li>
<li>LICENSE node_exporter NOTICE</li>
</ul>
</li>
<li>Move binary to the /usr/local/bin.&nbsp;&nbsp;
<ul>
<li>sudo mv node_exporter /usr/local/bin/</li>
</ul>
</li>
<li>Verify that you can run the binary.&nbsp;
<ul>
<li>$node_exporter --version</li>
</ul>
</li>
<li>Node Exporter has a lot of plugins that we can enable. If you run Node Exporter help you will get all the options.&nbsp;
<ul>
<li>$node_exporter --help</li>
</ul>
</li>
<li>Enable login controller: &ndash;collector.logind We&rsquo;re going to enable the login controller, just for the demo.&nbsp;
<ul>
<li>$sudo vim /etc/systemd/system/node_exporter.service</li>
<li>paste the following,&nbsp;Replace Prometheus user and group to node_exporter, and update the ExecStart command.</li>
<li>[Unit]<br />Description=Node Exporter<br />Wants=network-online.target<br />After=network-online.target<br />StartLimitIntervalSec=500<br />StartLimitBurst=5<br />[Service]<br />User=node_exporter<br />Group=node_exporter<br />Type=simple<br />Restart=on-failure<br />RestartSec=5s<br />ExecStart=/usr/local/bin/node_exporter \<br /> --collector.logind<br />[Install]<br />WantedBy=multi-user.target</li>
<li>save and exit.</li>
</ul>
</li>
<li>To automatically start the Node Exporter after reboot, enable the service.&nbsp;
<ul>
<li>$sudo systemctl enable node_exporter</li>
</ul>
</li>
<li>Then start the Node Exporter.&nbsp;
<ul>
<li>$sudo systemctl start node_exporter</li>
</ul>
</li>
<li>Check the status of Node Exporter with the following command:&nbsp;
<ul>
<li>$sudo systemctl status node_exporter</li>
</ul>
</li>
<li>At this point, we have only a single target in our Prometheus. There are many different service discovery mechanisms built into Prometheus. For example, Prometheus can dynamically discover targets in AWS, GCP, and other clouds based on the labels. In the following tutorials, I&rsquo;ll give you a few examples of deploying Prometheus in a cloud-specific environment. For this tutorial, let&rsquo;s keep it simple and keep adding static targets. Also, I have a lesson on how to deploy and manage Prometheus in the Kubernetes cluster.</li>
<li>Create a static target, you need to add job_name with static_configs.
<ul>
<li>$sudo vim /etc/prometheus/prometheus.yml</li>
<li>- job_name: node_export<br />&nbsp; static_configs:<br /> - targets: ["localhost:9100"]</li>
<li>By default, Node Exporter will be exposed on port 9100.</li>
</ul>
</li>
<li>Since we enabled lifecycle management via API calls, we can reload the Prometheus config without restarting the service and causing downtime.</li>
<li>Before, restarting check if the config is valid.
<ul>
<li>$promtool check config /etc/prometheus/prometheus.yml&nbsp; (success: /etc/prometheus/prometheus.yml is valid prometheus config file syntax)</li>
</ul>
</li>
<li>Then, you can use a POST request to reload the config.&nbsp;
<ul>
<li>$curl -X POST <a href="http://localhost:9090/-/reload">http://localhost:9090/-/reload</a></li>
</ul>
</li>
<li>Check the targets section.&nbsp;
<ul>
<li>open browser and run $http://192.168.171.103:9090/targets</li>
</ul>
</li>
</ul>
</li>
<li>Install Grafana on Ubuntu 22.04
<ul>
<li>To visualize metrics we can use Grafana. There are many different data sources that Grafana supports, one of them is Prometheus.</li>
<li>All the dependencies are installed.&nbsp;
<ul>
<li>$sudo apt-get install -y apt-transport-https software-properties-common</li>
</ul>
</li>
<li>Add the GPG key.&nbsp;
<ul>
<li>$wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -</li>
</ul>
</li>
<li>Add this repository for stable releases.&nbsp;
<ul>
<li>$echo "deb https://packages.grafana.com/oss/deb stable main" | sudo tee -a /etc/apt/sources.list.d/grafana.list</li>
</ul>
</li>
<li>After you add the repository, update and install Garafana.&nbsp;
<ul>
<li>$sudo apt-get update</li>
</ul>
</li>
<li>Install Grafana:&nbsp;
<ul>
<li>$sudo apt-get -y install grafana</li>
</ul>
</li>
<li>To automatically start the Grafana after reboot, enable the service.&nbsp;
<ul>
<li>$sudo systemctl enable grafana-server</li>
</ul>
</li>
<li>Start the Grafana.&nbsp;
<ul>
<li>$sudo systemctl start grafana-server</li>
</ul>
</li>
<li>Check the status of Grafana, run the following command:&nbsp;
<ul>
<li>$sudo systemctl status grafana-server</li>
</ul>
</li>
<li>Access Grafana:&nbsp;
<ul>
<li>open browser:&nbsp;<code>http://&lt;ip&gt;:3000</code>&nbsp;and log in to the Grafana using default credentials. The username is admin, and the password is admin as well.</li>
</ul>
</li>
<li>To visualize metrics, you need to add a data source first.&nbsp;
<ul>
<li>Click Add your first data source and click Prometheus from the list.</li>
<li>connection: Prometheus server url: <a href="http://192.168.171.103:9090">http://192.168.171.103:9090</a>&nbsp;save and test</li>
</ul>
</li>
<li>Add Dashboard for better vew:
<ul>
<li>Click on Import Dashboard paste this code&nbsp;<mark>1860</mark>&nbsp;and click on load,&nbsp;Select the Datasource=prometheus and click on Import</li>
</ul>
</li>
</ul>
</li>
<li>Add Jenkins target in prometheus server.
<ul>
<li>Install Prometheus Plugin and integrate with Prometheus server in Jenkins.
<ul>
<li>Go to Manage Jenkins/Plugins/search prometheus metrics and install.</li>
</ul>
</li>
<li>To create a static target, you need to add job_name with static_configs. go to Prometheus server.</li>
<li>$sudo vim /etc/prometheus/prometheus.yml&nbsp;</li>
<li>- job_name: 'jenkins'<br />&nbsp; metrics_path: '/prometheus'<br />&nbsp; static_configs:<br />&nbsp; &nbsp; &nbsp;- targets: ['192.168.171.101:8080']</li>
<li>copy &amp; paste does not work than type in the file and save it &amp; Exit.</li>
<li>Before, restarting check if the config is valid.&nbsp;
<ul>
<li>$promtool check config /etc/prometheus/prometheus.yml (SUCCESS: /etc/prometheus/prometheus.yml is valid prometheus config file syntax),&nbsp;</li>
</ul>
</li>
<li>Then, you can use a POST request to reload the config.&nbsp;
<ul>
<li>$curl -X POST <a href="http://localhost:9090/-/reload">http://localhost:9090/-/reload</a></li>
</ul>
</li>
<li>Check the targets section.&nbsp; In browser of prometheus: <a href="http://192.168.171.103/9090/targets">http://192.168.171.103/9090/targets</a></li>
<li><a href="https://stardistributors.co.uk/devops/devops_tools/projects/netflix/netflix11.jpg" target="_blank" rel="noopener"><img src="https://stardistributors.co.uk/devops/devops_tools/projects/netflix/netflix11.jpg" alt="" width="706" height="379" /></a></li>
<li>Let&rsquo;s add Dashboard for a better view in Grafana:&nbsp;&nbsp;
<ul>
<li>Click On Dashboard &ndash;&gt; + symbol &ndash;&gt; Import Dashboard,&nbsp;Use Id&nbsp;<code>9964</code>&nbsp;and click on load</li>
</ul>
</li>
<li>Select the data source and click on Import,&nbsp;Now you will see the Detailed overview of Jenkins.</li>
<li><a href="https://stardistributors.co.uk/devops/devops_tools/projects/netflix/netflix12.jpg" target="_blank" rel="noopener"><img src="https://stardistributors.co.uk/devops/devops_tools/projects/netflix/netflix12.jpg" alt="" width="700" height="424" /></a></li>
</ul>
</li>
<li>Code</li>
</ul>
</details></li>
<li><details><summary>Monitoring for application:</summary>
<ul>
<li>Run CICD pipeline</li>
<li>check the metrics in grafana for jenkins cicd job running, 1 executor is in use and 1 is free.</li>
<li>youtube5</li>
<li>CICD job completed.</li>
</ul>
</details></li>
<li><details><summary>Integrate prometheus with EKS and import Grafana monitoring Dashboard for Kubernetes.</summary>
<ul>
<li>Code</li>
<li>Code</li>
</ul>
</details></li>
<li><details><summary>Configure Github Wehbook Trigger.</summary>
<ul>
<li>Code</li>
<li>Code</li>
</ul>
</details></li>
<li><details><summary>Access Application deployed on kubernetes pod </summary>
<ul>
<li>Code</li>
<li>Code</li>
</ul>
</details></li>
<li>Code</li>
</ul>
</details></li>
