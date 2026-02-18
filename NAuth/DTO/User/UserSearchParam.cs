using System.Text.Json.Serialization;

namespace NAuth.DTO.User
{
    public class UserSearchParam
    {
        [JsonPropertyName("searchTerm")]
        public string SearchTerm { get; set; }

        [JsonPropertyName("page")]
        public int Page { get; set; } = 1;

        [JsonPropertyName("pageSize")]
        public int PageSize { get; set; } = 10;
    }
}
