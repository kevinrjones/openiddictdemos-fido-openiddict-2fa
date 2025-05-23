using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Rsk.AspNetCore.Fido;
using Rsk.AspNetCore.Fido.Dtos;
using Rsk.AspNetCore.Fido.Models;
using Velusia.Server.Data;
using Velusia.Server.ViewModels.Fido;

namespace Velusia.Server.Controllers;

public class FidoController : Controller
{
    private readonly IFidoAuthentication _fido;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;

    public FidoController(IFidoAuthentication fido, SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager)
    {
        _fido = fido;
        _signInManager = signInManager;
        _userManager = userManager;
    }

    public IActionResult StartRegistration(string returnUrl)
    {
        StartRegistration model = new()
        {
            ReturnUrl = returnUrl
        };
        if (User?.Identity?.IsAuthenticated == true)
        {
            return View(model);
        }
        else
        {
            return Redirect("/Identity/Account/Login?returnUrl=/fido/startregistration");
        }
    }

    [HttpPost]
    public async Task<ActionResult> Register(StartRegistration model)
    {
        if (ModelState.IsValid)
        {
            FidoRegistrationChallenge challenge =
                await _fido.InitiateRegistration(User?.Identity?.Name, model.DeviceName);

            var register = new Register { ReturnUrl = model.ReturnUrl, Challenge = challenge.ToBase64Dto() };

            return View(register);
        }

        return View("StartRegistration", model);
    }


    [HttpPost]
    public async Task<IActionResult> CompleteRegistration(
        [FromBody] Base64FidoRegistrationResponse registrationResponse)
    {
        IFidoRegistrationResult result = await _fido.CompleteRegistration(registrationResponse.ToFidoResponse());

        if (result.IsError)
        {
            return BadRequest(result.ErrorDescription);
        }

        return Ok();
    }

    public async Task<IActionResult> FidoLogin(string returnUrl)
    {
        var result = await HttpContext.AuthenticateAsync(IdentityConstants.TwoFactorUserIdScheme);

        if (result.Succeeded)
        {
            var claims = result.Principal.Claims.ToList();

            string userName = claims.FirstOrDefault(c => c.Type == "userName")?.Value;

            var challenge = await _fido.InitiateAuthentication(userName);
            
            var model = new AuthenticationModel()
                {Challenge = challenge.ToBase64Dto(), ReturnUrl = returnUrl};

            return View(model);
        }

        return new RedirectResult("/Home/Error");
    }

    [HttpPost]
    public async Task<IActionResult> FidoCompleteLogin(
        [FromBody] Base64FidoAuthenticationResponse authenticationResponse)
    {
        
        var result = await _fido.CompleteAuthentication(authenticationResponse.ToFidoResponse());

        if (result.IsSuccess)
        {
            var authenticateResult = await HttpContext.AuthenticateAsync(IdentityConstants.TwoFactorUserIdScheme);

            var claims = authenticateResult.Principal.Claims.ToList();
            string rememberMeClaim = claims.FirstOrDefault(c => c.Type == "rememberme")?.Value;
            bool rememberMe = bool.Parse(rememberMeClaim ?? "false");
            string userName = claims.FirstOrDefault(c => c.Type == "userName")?.Value;
            
            ApplicationUser user = await _userManager.FindByNameAsync(userName);
            
            await _signInManager.SignInAsync(user, rememberMe);

        }
        
        await HttpContext.SignOutAsync(IdentityConstants.TwoFactorUserIdScheme);

        if (result.IsError) return BadRequest(result.ErrorDescription);

        return Ok();

    }

}











