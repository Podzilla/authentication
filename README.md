# Authentication Microservice

## Overview
The Authentication Microservice is a core component of the Podzilla system, designed to handle user authentication and authorization securely. Built as a standalone microservice, it provides robust mechanisms for user management, secure access control, and session handling, ensuring seamless integration with other services in the Podzilla ecosystem.

## Badges
![Java](https://img.shields.io/badge/Java-17-blue)
![Spring Boot](https://img.shields.io/badge/Spring_Boot-3.2.0-green)
![Spring Security](https://img.shields.io/badge/Spring_Security-6.2.0-brightgreen)
![Docker](https://img.shields.io/badge/Docker-24.0-blue)
![JUnit](https://img.shields.io/badge/JUnit-5.10.0-orange)
![Checkstyle](https://img.shields.io/badge/Checkstyle-10.12.0-blueviolet)
![JDBC](https://img.shields.io/badge/JDBC-MySQL_8.0-blue)
![Lombok](https://img.shields.io/badge/Lombok-1.18.30-red)
![Redis](https://img.shields.io/badge/Redis-7.2-red)
![Build Status](https://img.shields.io/github/actions/workflow/status/Podzilla/authentication/ci.yml?branch=main&label=CI%2FCD)

## Features
- **Login**: Secure user authentication using email/username and password with JWT-based access tokens.
- **Logout**: Invalidate user sessions and refresh tokens.
- **Register**: Create new user accounts with email verification.
- **Update User Data**: Allow users to update their profile information securely.
- **Activate/Deactivate Users**: Admin functionality to manage user account statuses.
- **Refresh Access Token**: Generate new access tokens using refresh tokens for seamless user experience.
- **Role-Based Access Control**: Support for different user roles (e.g., admin, user) with fine-grained permissions.

## Code Style
The project adheres to Java conventions and best practices for maintainability and readability:
- **Naming Conventions**:
  - Classes: PascalCase (e.g., `UserService`, `AuthController`)
  - Methods and Variables: camelCase (e.g., `authenticateUser`, `userId`)
  - Constants: UPPER_SNAKE_CASE (e.g., `MAX_LOGIN_ATTEMPTS`)
  - Packages: Lowercase with meaningful hierarchy (e.g., `com.podzilla.auth.service`)
- **Best Practices**:
  - Use meaningful names that reflect purpose (e.g., `generateJwtToken` instead of `genToken`).
  - Follow single-responsibility principle for methods and classes.
  - Include JavaDoc for public methods and classes.
  - Enforce code quality with Checkstyle to ensure consistent formatting and adherence to standards.
  - Avoid magic numbers/strings; use constants instead.
  - Handle exceptions gracefully with proper logging.

## Architecture
The Authentication Microservice follows a **microservice architecture** with **Domain-Driven Design (DDD)** and **Clean Architecture** principles. The codebase is organized into distinct layers to ensure separation of concerns:
- **Models**: Represent domain entities (e.g., `User`, `Role`).
- **Repositories**: Handle data persistence using JDBC for MySQL and Redis for caching.
- **Services**: Contain business logic (e.g., `AuthService`, `UserService`).
- **Controllers**: Expose RESTful endpoints for client interaction (e.g., `/api/auth/login`).
- **DTOs (Data Transfer Objects)**: Used for request/response payloads to decouple API contracts from domain models.

The microservice communicates with other Podzilla services via REST APIs and uses Redis for fast, in-memory token storage. Spring Security is leveraged for authentication and authorization, ensuring secure access control.

## Installation and Running

### Prerequisites
- Java 17
- Maven 3.8.6+
- Docker 24.0+
- MySQL 8.0+
- Redis 7.2+
- Git

### Setup
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Podzilla/authentication.git
   cd authentication
   ```

2. **Configure Environment**:
   - Create a `.env` file based on `.env.example` and update with your MySQL and Redis credentials:
     ```env
     SPRING_DATASOURCE_URL=jdbc:mysql://localhost:3306/auth_db
     SPRING_DATASOURCE_USERNAME=root
     SPRING_DATASOURCE_PASSWORD=your_password
     SPRING_REDIS_HOST=localhost
     SPRING_REDIS_PORT=6379
     ```

3. **Build the Project**:
   ```bash
   mvn clean install
   ```

4. **Run the Application**:
   ```bash
   mvn spring-boot:run
   ```
   The service will be available at `http://localhost:8080`.

5. **Run with Docker**:
   ```bash
   docker build -t podzilla-authentication .
   docker run -p 8080:8080 --env-file .env podzilla-authentication
   ```

6. **Access Swagger UI**:
   - Navigate to `http://localhost:8080/swagger-ui.html` to explore and test API endpoints.

7. **Run Tests**:
   ```bash
   mvn test
   ```
   - Unit and integration tests are written using JUnit 5.
   - Code coverage reports are generated and available in `target/site/jacoco`.

## How to Contribute
We welcome contributions to enhance the Authentication Microservice! To contribute:
1. Fork the repository.
2. Create a new branch (`git checkout -b feature/your-feature`).
3. Make your changes and ensure tests pass (`mvn test`).
4. Run Checkstyle to verify code quality:
   ```bash
   mvn checkstyle:check
   ```
5. Commit your changes with a clear message (`git commit -m "Add your feature"`).
6. Push to your branch (`git push origin feature/your-feature`).
7. Open a pull request with a detailed description of your changes.
8. Ensure your PR passes CI/CD checks.

Please follow the code style guidelines and include tests for new features or bugfixes.
