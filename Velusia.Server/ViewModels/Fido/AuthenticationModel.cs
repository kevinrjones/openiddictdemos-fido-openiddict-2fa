using Rsk.AspNetCore.Fido.Dtos;

namespace Velusia.Server.ViewModels.Fido;

public class AuthenticationModel
{
    public string ReturnUrl { get; set; }
    public Base64FidoAuthenticationChallenge Challenge { get; set; }
}