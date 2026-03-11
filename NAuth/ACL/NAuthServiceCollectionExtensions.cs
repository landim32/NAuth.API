using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using NAuth.ACL.Interfaces;

namespace NAuth.ACL
{
    public static class NAuthServiceCollectionExtensions
    {
        public static IServiceCollection AddNAuth(this IServiceCollection services)
        {
            return services.AddNAuth<SettingsTenantProvider>();
        }

        public static IServiceCollection AddNAuth<TTenantProvider>(this IServiceCollection services)
            where TTenantProvider : class, ITenantProvider
        {
            services.AddScoped<ITenantProvider, TTenantProvider>();
            services.AddTransient<TenantDelegatingHandler>();

            services.AddHttpClient<IUserClient, UserClient>()
                .AddHttpMessageHandler<TenantDelegatingHandler>();

            services.AddHttpClient<IRoleClient, RoleClient>()
                .AddHttpMessageHandler<TenantDelegatingHandler>();

            return services;
        }

        public static IServiceCollection AddNAuthAuthentication(this IServiceCollection services, string scheme = "NAuth")
        {
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = scheme;
                options.DefaultChallengeScheme = scheme;
            })
            .AddScheme<AuthenticationSchemeOptions, NAuthHandler>(scheme, null);

            return services;
        }
    }
}
