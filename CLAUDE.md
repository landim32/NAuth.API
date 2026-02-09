# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

NAuth.API is the backend REST API for the NAuth authentication framework, built with .NET 8 and PostgreSQL. It provides JWT-based authentication with email verification, password recovery, role management, and user profile features. External packages (NAuth.DTO, NAuth.ACL, nauth-react) have been moved to their own repositories.

## Build & Test Commands

```bash
# Build entire solution
dotnet build

# Run all tests
dotnet test

# Run tests with coverage (used by CI)
dotnet test /p:CollectCoverage=true /p:CoverletOutputFormat=opencover

# Run a single test class
dotnet test NAuth.Test/NAuth.Test.csproj --filter "FullyQualifiedName~UserServiceTests"

# Run a single test method
dotnet test NAuth.Test/NAuth.Test.csproj --filter "FullyQualifiedName~UserServiceTests.TestMethodName"

# Docker full stack
docker compose up --build
```

## Architecture

Clean architecture with strict layer separation. Dependencies flow inward only:

```
NAuth.API → NAuth.Application → NAuth.Domain ← NAuth.Infra
                                     ↑
                              NAuth.Infra.Interfaces
```

- **NAuth.API** — ASP.NET Core controllers (UserController, RoleController), Startup.cs configures all services, Swagger, CORS, health checks, and the custom `NAuthHandler` authentication scheme.
- **NAuth.Application** — `Initializer.cs` is the single DI composition root. All service/repository/factory registrations happen here.
- **NAuth.Domain** — Business logic lives in `UserService` (largest file ~877 lines) and `RoleService`. Domain models (UserModel, RoleModel, etc.) implement interfaces from Infra.Interfaces. Custom exceptions in `Exceptions/`. Factory pattern for model creation.
- **NAuth.Infra** — EF Core 9 with PostgreSQL (Npgsql), lazy loading proxies. `NAuthContext` defines all entity configurations. Repository pattern with `UnitOfWork` for transactions.
- **NAuth.Infra.Interfaces** — Repository and model interfaces. Keeps Domain independent of Infra.
- **NAuth.DTO** — Shared DTOs (separate repository, NuGet package). Referenced as PackageReference.
- **NAuth.ACL** — Anti-Corruption Layer (separate repository, NuGet package). Referenced as PackageReference.
- **NAuth.Test** — xUnit + Moq tests organized by layer: `Domain/` (model + service tests), `Infra/` (repository tests with EF InMemory), `ACL/` (client + handler tests).

## Key Patterns

- **Repository + UnitOfWork**: All data access through repository interfaces. Transactions managed via `UnitOfWork`/`TransactionDisposable`.
- **Factory Pattern**: `UserDomainFactory`, `RoleDomainFactory` etc. for consistent model initialization. Repositories are generic over model and factory types.
- **JWT Authentication**: HMAC-SHA256, issuer/audience "NAuth"/"NAuth.API". Claims include userId, email, roles, hash, ipAddress, userAgent, fingerprint, isAdmin. Secret must be minimum 64 characters.
- **Entity ↔ Model ↔ DTO mapping**: EF entities map to domain models in repositories; controllers map models to DTOs for API responses.

## Configuration

- `appsettings.Development.json` — Local dev with localhost PostgreSQL
- `appsettings.Docker.json` — Uses environment variable placeholders (`${ConnectionStrings__NAuthContext}`, `${NAuth__JwtSecret}`)
- `.env` file (from `.env.example`) — Required for Docker Compose; contains DB credentials, JWT secret, ports
- Settings DTOs: `NAuthSetting` (JWT/bucket config), `MailerSendSetting` (email), `NToolSetting` (external tools API)

## Database

PostgreSQL with EF Core. Key entities: `Users`, `Roles`, `UserRoles` (many-to-many join), `UserAddresses`, `UserPhones`, `UserDocuments`. All configured via Fluent API in `NAuthContext`. Uses sequences for ID generation.

Scaffold context from existing DB: `./createContext.ps1`

## Versioning & CI/CD

- **GitVersion** (ContinuousDelivery mode) for semantic versioning
- Commit message prefixes control version bumps: `major:`/`breaking:`, `feature:`/`minor:`, `fix:`/`patch:`
- GitHub Actions: `sonarcloud.yml` (quality gate), `version-tag.yml` (auto-tagging)

## Documentation

All generated documentation must:
- Be in **Markdown** format (`.md`)
- Be saved in the `docs/` directory
- Use **UPPER_SNAKE_CASE** for file names (e.g., `docs/API_ENDPOINTS.md`, `docs/DATABASE_SCHEMA.md`)

## Docker

Two containers orchestrated via `docker-compose.yml`:
- **nauth-postgres** — PostgreSQL with custom init scripts
- **nauth-api** — Multi-stage .NET build, runs as non-root `appuser`, ports 5004/5005
- Requires external Docker network: `emagine-network`
