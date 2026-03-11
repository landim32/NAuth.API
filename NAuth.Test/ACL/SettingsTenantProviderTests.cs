using Microsoft.Extensions.Options;
using Moq;
using NAuth.ACL;
using NAuth.DTO.Settings;
using Xunit;

namespace NAuth.Test.ACL
{
    public class SettingsTenantProviderTests
    {
        [Fact]
        public void GetTenantId_WithConfiguredTenantId_ShouldReturnValue()
        {
            // Arrange
            var mockOptions = new Mock<IOptions<NAuthSetting>>();
            mockOptions.Setup(o => o.Value).Returns(new NAuthSetting { TenantId = "tenant-abc" });
            var provider = new SettingsTenantProvider(mockOptions.Object);

            // Act
            var result = provider.GetTenantId();

            // Assert
            Assert.Equal("tenant-abc", result);
        }

        [Fact]
        public void GetTenantId_WithNullTenantId_ShouldReturnNull()
        {
            // Arrange
            var mockOptions = new Mock<IOptions<NAuthSetting>>();
            mockOptions.Setup(o => o.Value).Returns(new NAuthSetting());
            var provider = new SettingsTenantProvider(mockOptions.Object);

            // Act
            var result = provider.GetTenantId();

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public void GetTenantId_WithEmptyTenantId_ShouldReturnEmpty()
        {
            // Arrange
            var mockOptions = new Mock<IOptions<NAuthSetting>>();
            mockOptions.Setup(o => o.Value).Returns(new NAuthSetting { TenantId = "" });
            var provider = new SettingsTenantProvider(mockOptions.Object);

            // Act
            var result = provider.GetTenantId();

            // Assert
            Assert.Equal(string.Empty, result);
        }
    }
}
