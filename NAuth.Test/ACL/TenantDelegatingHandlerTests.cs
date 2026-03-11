using Moq;
using NAuth.ACL;
using NAuth.ACL.Interfaces;
using Xunit;

namespace NAuth.Test.ACL
{
    public class TenantDelegatingHandlerTests
    {
        private readonly Mock<ITenantProvider> _mockTenantProvider;

        public TenantDelegatingHandlerTests()
        {
            _mockTenantProvider = new Mock<ITenantProvider>();
        }

        private (TenantDelegatingHandler handler, MockInnerHandler inner) CreateHandler()
        {
            var inner = new MockInnerHandler();
            var handler = new TenantDelegatingHandler(_mockTenantProvider.Object)
            {
                InnerHandler = inner
            };
            return (handler, inner);
        }

        [Fact]
        public async Task SendAsync_WithTenantId_ShouldAddHeader()
        {
            // Arrange
            _mockTenantProvider.Setup(p => p.GetTenantId()).Returns("tenant-123");
            var (handler, _) = CreateHandler();
            var client = new HttpClient(handler);
            var request = new HttpRequestMessage(HttpMethod.Get, "https://localhost/test");

            // Act
            await client.SendAsync(request);

            // Assert
            Assert.True(request.Headers.Contains("X-Tenant-Id"));
            Assert.Equal("tenant-123", request.Headers.GetValues("X-Tenant-Id").First());
        }

        [Fact]
        public async Task SendAsync_WithNullTenantId_ShouldNotAddHeader()
        {
            // Arrange
            _mockTenantProvider.Setup(p => p.GetTenantId()).Returns((string?)null);
            var (handler, _) = CreateHandler();
            var client = new HttpClient(handler);
            var request = new HttpRequestMessage(HttpMethod.Get, "https://localhost/test");

            // Act
            await client.SendAsync(request);

            // Assert
            Assert.False(request.Headers.Contains("X-Tenant-Id"));
        }

        [Fact]
        public async Task SendAsync_WithEmptyTenantId_ShouldNotAddHeader()
        {
            // Arrange
            _mockTenantProvider.Setup(p => p.GetTenantId()).Returns(string.Empty);
            var (handler, _) = CreateHandler();
            var client = new HttpClient(handler);
            var request = new HttpRequestMessage(HttpMethod.Get, "https://localhost/test");

            // Act
            await client.SendAsync(request);

            // Assert
            Assert.False(request.Headers.Contains("X-Tenant-Id"));
        }

        [Fact]
        public async Task SendAsync_WithExistingHeader_ShouldReplaceIt()
        {
            // Arrange
            _mockTenantProvider.Setup(p => p.GetTenantId()).Returns("tenant-new");
            var (handler, _) = CreateHandler();
            var client = new HttpClient(handler);
            var request = new HttpRequestMessage(HttpMethod.Get, "https://localhost/test");
            request.Headers.TryAddWithoutValidation("X-Tenant-Id", "tenant-old");

            // Act
            await client.SendAsync(request);

            // Assert
            var values = request.Headers.GetValues("X-Tenant-Id").ToList();
            Assert.Single(values);
            Assert.Equal("tenant-new", values[0]);
        }

        public class MockInnerHandler : DelegatingHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK));
            }
        }
    }
}
