namespace JwtCleanArch.Application.Common
{
    public class PaginatedResult<T>
    {
        public IEnumerable<T> Items { get; set; } = new List<T>();

        public int PageNumber { get; set; }
        public int PageSize { get; set; }

        public int TotalCount { get; set; }
        public int TotalPages { get; set; }

        public bool HasPreviousPage => PageNumber > 1;
        public bool HasNextPage => PageNumber < TotalPages;

        public PaginatedResult(IEnumerable<T> items, int count, int pageNumber, int pageSize)
        {
            Items = items;
            TotalCount = count;
            PageNumber = pageNumber;
            PageSize = pageSize;
            TotalPages = (int)Math.Ceiling(count / (double)pageSize);
        }
    }
}
