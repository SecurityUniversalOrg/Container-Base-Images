# Container-Base-Images

## Introduction

Welcome to our GitHub repository dedicated to providing secure and modular Docker base images for web applications. As a DevSecOps-focused organization, we understand the critical importance of security and efficiency in application development. This repository offers a range of Docker images, each tailored to specific needs while ensuring the highest security standards.

## Docker Images
### ubuntu_22_base

* **Description**: This image serves as a plain and minimal Ubuntu 22 base. It's a lightweight starting point, containing only the essential components of Ubuntu 22, with no additional software.
* **Purpose**: Ideal for those who need a clean, secure Ubuntu environment as a foundation for building their custom applications.

### web_apache_base

* **Base**: ubuntu_22_base
* **Description**: Built upon the ubuntu_22_base image, this Docker image includes Apache and its associated libraries.
* **Purpose**: Designed for developers who require a pre-configured Apache environment, this image saves time and ensures a secure setup for hosting web applications.

### python_flask_base

* **Base**: web_apache_base
* **Description**: Extending the web_apache_base, this image incorporates Python Flask and other necessary libraries.
* **Purpose**: Tailored for Python developers using Flask, this image offers a ready-to-use environment for Flask-based web applications, ensuring both security and ease of deployment.

## Security Measures

* **Regular Updates**: All images are regularly updated to include the latest security patches and updates.
* **Minimalist Design**: Each image contains only the necessary components, reducing the attack surface.
* **Best Practices**: Configurations and installations follow industry best practices for security.

## Usage

To use these images, ensure you have Docker installed on your system. You can pull these images using the following commands:

```bash
docker pull securityuniversal/ubuntu_22_base
docker pull securityuniversal/web_apache_base
docker pull securityuniversal/python_flask_base
```


## Contributing

Contributions to improve the security and efficiency of these images are welcome. Please submit your pull requests or open issues to discuss potential changes or additions.

## License

This project is licensed under the GPL-3.0 License.

## Contact

For any queries or support, please contact [admin@securityuniversal.com](mailto:admin@securityuniversal.com).