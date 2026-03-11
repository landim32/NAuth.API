using NAuth.ACL.Interfaces;

namespace NAuth.ACL
{
    public class TenantDelegatingHandler : DelegatingHandler
    {
        private readonly ITenantProvider _tenantProvider;

        public TenantDelegatingHandler(ITenantProvider tenantProvider)
        {
            _tenantProvider = tenantProvider;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var tenantId = _tenantProvider.GetTenantId();

            if (!string.IsNullOrEmpty(tenantId))
            {
                request.Headers.Remove("X-Tenant-Id");
                request.Headers.TryAddWithoutValidation("X-Tenant-Id", tenantId);
            }

            return base.SendAsync(request, cancellationToken);
        }
    }
}
