using System.Text.Json.Serialization;

namespace NAuth.DTO.User
{
    public class RoleInfo
    {
        [JsonPropertyName("roleId")]
        public long RoleId { get; set; }

        [JsonPropertyName("slug")]
        public string Slug { get; set; }

        [JsonPropertyName("name")]
        public string Name { get; set; }
    }
}
