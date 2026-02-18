using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace NAuth.DTO.User
{
    public class PagedResult<T>
    {
        [JsonPropertyName("items")]
        public IList<T> Items { get; set; }

        [JsonPropertyName("page")]
        public int Page { get; set; }

        [JsonPropertyName("pageSize")]
        public int PageSize { get; set; }

        [JsonPropertyName("totalCount")]
        public int TotalCount { get; set; }

        [JsonPropertyName("totalPages")]
        public int TotalPages { get; set; }

        [JsonPropertyName("hasPreviousPage")]
        public bool HasPreviousPage { get; set; }

        [JsonPropertyName("hasNextPage")]
        public bool HasNextPage { get; set; }

        public PagedResult()
        {
            Items = new List<T>();
        }

        public PagedResult(IList<T> items, int page, int pageSize, int totalCount)
        {
            Items = items ?? new List<T>();
            Page = page;
            PageSize = pageSize;
            TotalCount = totalCount;
            TotalPages = (int)System.Math.Ceiling(totalCount / (double)pageSize);
            HasPreviousPage = page > 1;
            HasNextPage = page < TotalPages;
        }
    }
}
