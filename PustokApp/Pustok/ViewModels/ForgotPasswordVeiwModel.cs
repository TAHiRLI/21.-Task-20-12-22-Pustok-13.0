using System.ComponentModel.DataAnnotations;

namespace Pustok.ViewModels
{
    public class ForgotPasswordVeiwModel
    {
        [MaxLength(100)]
        [Required]
        public string Email { get; set; }
    }
}
