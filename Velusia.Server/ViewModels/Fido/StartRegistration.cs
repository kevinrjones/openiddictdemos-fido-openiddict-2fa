using System.ComponentModel.DataAnnotations;

namespace Velusia.Server.ViewModels.Fido;

public class StartRegistration
{
    [Required]
    [Display(Name = "Device Name")]
    public string DeviceName { get; set; }

    public string? ReturnUrl { get; set; }
}