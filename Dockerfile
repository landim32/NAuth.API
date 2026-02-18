#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy solution and project files first for better layer caching
COPY ["NAuth.API/NAuth.API.csproj", "NAuth.API/"]
COPY ["NAuth.Application/NAuth.Application.csproj", "NAuth.Application/"]
COPY ["NAuth.Domain/NAuth.Domain.csproj", "NAuth.Domain/"]
COPY ["NAuth.Infra/NAuth.Infra.csproj", "NAuth.Infra/"]
COPY ["NAuth.Infra.Interfaces/NAuth.Infra.Interfaces.csproj", "NAuth.Infra.Interfaces/"]
COPY ["NAuth/NAuth.csproj", "NAuth/"]

# Restore dependencies
RUN dotnet restore "NAuth.API/NAuth.API.csproj"

# Copy source code (sensitive files are excluded via .dockerignore)
# .dockerignore prevents .env files, secrets, and other sensitive data from being copied
COPY . .
WORKDIR "/src/NAuth.API"
RUN dotnet build "NAuth.API.csproj" -c Release -o /app/build

# Publish stage
FROM build AS publish
RUN dotnet publish "NAuth.API.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app

# Install libgdiplus with pango support for image processing and curl for health check
RUN apt-get update && apt-get install -y --allow-unauthenticated \
    libgif-dev \
    autoconf \
    libtool \
    automake \
    build-essential \
    gettext \
    libglib2.0-dev \
    libcairo2-dev \
    libtiff-dev \
    libexif-dev \
    libpango1.0-dev \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Build and install libgdiplus from source
RUN git clone https://github.com/mono/libgdiplus.git /tmp/libgdiplus && \
    cd /tmp/libgdiplus && \
    ./autogen.sh --with-pango --prefix=/usr && \
    make && \
    make install && \
    cd / && \
    rm -rf /tmp/libgdiplus

# Create non-root user early for better security
RUN useradd -m -s /bin/bash appuser

# Copy published app
COPY --from=publish /app/publish .

# Copy SSL certificate (only this specific certificate is needed)
COPY ["NAuth.API/emagine.pfx", "./emagine.pfx"]

# Set ownership to non-root user
RUN chown -R appuser:appuser /app

# Set environment variables
ENV ASPNETCORE_ENVIRONMENT=Docker
ENV ASPNETCORE_URLS=http://+:80;https://+:443

# Expose ports
EXPOSE 80
EXPOSE 443

# Health check - using root route that returns application status
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:80/ || exit 1

# Run as non-root user for security
USER appuser

ENTRYPOINT ["dotnet", "NAuth.API.dll"]
