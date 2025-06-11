# GPUs-scheduler

# GPU computing power scheduling system design ideas
According to the requirements of readme.txt, I will design a streamlined localized GPU computing power scheduling system. The following is my design idea:

### 1. System architecture
The system will adopt a layered architecture design:

- Core layer: GPU resource management and scheduling
- Interface layer: Provide standard GPU computing power call API
- Monitoring layer: GPU resource monitoring system
- Application layer: Sample application (deepseek-7b call case)
### 2. Key components
#### 2.1 GPU Resource Manager
- Responsible for discovering and managing multiple NVIDIA 4090 graphics cards
- Parameterized configuration of graphics card quantity and attributes through YAML configuration files
- Use CUDA driver interface to interact with GPU hardware
#### 2.2 Scheduling system
- Realize multi-tenant computing power isolation
- Dynamically allocate GPU resources to ensure maximum computing power utilization
- Support graphics card numbering and single-tenant computing power dynamic allocation
#### 2.3 Standard API interface
- Provide a simple and unified GPU computing power call interface
- Support different applications (such as deepseek-7b) to call GPU resources
#### 2.4 Resource monitoring system
- Real-time monitoring of GPU usage
- Provide basic resource usage statistics and reports
### 3. Technology selection
- Programming language: Golang (try to avoid using third-party libraries)
- Configuration format: YAML
- System environment: Debian system
### 4. Project structure
```
/
├── internal/ # Internal package
│ ├── auth/ # Authentication related
│ ├── config/ # Configuration management
│ ├── gpu/ # GPU resource management
│ ├── monitor/ # Monitoring system
│ └── scheduler/ # Scheduling algorithm implementation
├── pkg/ # Public package
│ └── api/ # API interface definition
├── examples/ # Call example
│ └── client/ # Client example
├── configs/ # Configuration file
│ └── scheduler.yaml # Scheduler configuration
├── doc/ # Document
│ └── document.txt # Document description
├── web/ # Web interface
│ └── static/ # Static resources
├── README.md # English document
└── README.zh-CN.md # Chinese document
```

### 5. Implementation steps
1. Infrastructure construction:
- Create project structure and directory
- Design and implement configuration file format and loading mechanism
- Build basic log and error handling framework

2. GPU resource management:
- Implement GPU device discovery and initialization mechanism
- Develop device information collection and status update function
- Implement resource allocation and release mechanism

3. Scheduling system:
- Implement multi-tenant isolation mechanism
- Develop priority-based dynamic resource allocation algorithm
- Implement task queue and scheduling loop
- Add task status management and timeout processing

4. API interface:
- Design RESTful API interface specifications
- Implement task submission, query and management interfaces
- Add user authentication and permission control
- Provide SDK or client library

5. Monitoring system:
- Implement real-time monitoring of GPU resources
- Develop indicator collection and history recording functions
- Provide monitoring API and simple web interface
- Implement alarm mechanism

6. Sample application:
- Implement deepseek-7b model call case
- Develop client sample program
- Write usage documentation and sample instructions

### 6. Key technical points
1. GPU resource isolation: Use CUDA context or similar mechanism to achieve multi-tenant isolation
2. Dynamic scheduling algorithm: Dynamically allocate GPU according to task priority and resource requirements
3. Performance optimization: Minimize scheduling overhead and improve resource utilization
4. Fault tolerance mechanism: Handle GPU failure and task failure
5. Security mechanism: Implement tenant authentication and resource access control

### 7. Notes
- Do not use Docker, manage GPU resources directly on the host
- Keep the design simple and avoid over-design
- Minimize third-party dependencies unless necessary
- Ensure that the system can be horizontally expanded to support more GPU devices
- Prioritize system stability and resource isolation

### 8. Instructions
For detailed installation and usage instructions, please refer to [Document Directory](./doc/).