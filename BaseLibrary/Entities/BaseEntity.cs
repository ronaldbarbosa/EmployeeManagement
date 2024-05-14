using System.Text.Json.Serialization;

namespace BaseLibrary.Entities
{
    public class BaseEntity
    {
        public int Id { get; set; }
        public string? Name { get; set; }

        // One to many
        [JsonIgnore]
        public IList<Employee>? Employees { get; set; }
    }
}
