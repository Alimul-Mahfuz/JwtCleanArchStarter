namespace JwtCleanArch.Application.Common
{
    public class Result<T>
    {
        public bool Success { get; set; }
        public T Data { get; set; }
        public List<string> Errors { get; set; } = new();

        public static Result<T> Failure(params string[] errors)
            => new Result<T> { Success = false, Errors = errors.ToList() };

        public static Result<T> SuccessResult(T data)
            => new Result<T> { Success = true, Data = data };
    }
}
