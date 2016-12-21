using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Text;
using System.Threading.Tasks;
using System.Configuration;
using System.Threading;
using System.IO;
using Microsoft.WindowsAzure.MediaServices.Client;
using Microsoft.WindowsAzure.MediaServices.Client.ContentKeyAuthorization;
using Microsoft.WindowsAzure.MediaServices.Client.DynamicEncryption;

namespace MediaLibrary.Controllers
{
    public class ProtectMediaController : Controller
    {
        // GET: ProtectMedia
        private static readonly string _mediaServicesAccountName =
            ConfigurationManager.AppSettings["MediaServicesAccountName"];
        private static readonly string _mediaServicesAccountKey =
            ConfigurationManager.AppSettings["MediaServicesAccountKey"];
        private static CloudMediaContext myContext = null;
        private static MediaServicesCredentials _cachedCredentials = null;
        private static readonly string assetName = "DemoVideo2-mp4-Source - MBR";
        private static string tokenString = null;

        public ActionResult Index()
        {
            _cachedCredentials = new MediaServicesCredentials(
                    _mediaServicesAccountName,
                    _mediaServicesAccountKey);
            myContext = new CloudMediaContext(_cachedCredentials);

            // Use a LINQ Select query to get an asset.
            var assetInstance =
                from a in myContext.Assets
                where a.Name == assetName
                select a;
            // Reference the asset as an IAsset.
            IAsset myAsset = assetInstance.FirstOrDefault();
            IContentKey key = myAsset.ContentKeys[0];
            IContentKeyAuthorizationPolicy AutPol = myContext.ContentKeyAuthorizationPolicies.Where(a => a.Id == key.AuthorizationPolicyId).FirstOrDefault();
            IContentKeyAuthorizationPolicyOption AutPolOption = AutPol.Options.Skip(0).FirstOrDefault();
            string tokenTemplateString = AutPolOption.Restrictions.FirstOrDefault().Requirements;
            TokenRestrictionTemplate tokenTemplate = TokenRestrictionTemplateSerializer.Deserialize(tokenTemplateString);
            Guid rawkey = EncryptionUtils.GetKeyIdAsGuid(key.Id);
            if (tokenTemplate.TokenType == TokenType.SWT) //SWT
            {
                tokenString = TokenRestrictionTemplateSerializer.GenerateTestToken(tokenTemplate, null, rawkey, form.EndDate);

            }
            else // JWT
            {
                IList<Claim> myclaims = null;
                myclaims = form.GetTokenRequiredClaims;
                if (form.PutContentKeyIdentifier)
                    myclaims.Add(new Claim(TokenClaim.ContentKeyIdentifierClaimType, rawkey.ToString()));

                if (tokenTemplate.PrimaryVerificationKey.GetType() == typeof(SymmetricVerificationKey))
                {
                    InMemorySymmetricSecurityKey tokenSigningKey = new InMemorySymmetricSecurityKey((tokenTemplate.PrimaryVerificationKey as SymmetricVerificationKey).KeyValue);
                    signingcredentials = new SigningCredentials(tokenSigningKey, SecurityAlgorithms.HmacSha256Signature, SecurityAlgorithms.Sha256Digest);
                }
                else if (tokenTemplate.PrimaryVerificationKey.GetType() == typeof(X509CertTokenVerificationKey))
                {
                    X509Certificate2 cert = form.GetX509Certificate;
                    if (cert != null) signingcredentials = new X509SigningCredentials(cert);
                }
                JwtSecurityToken token = new JwtSecurityToken(issuer: form.GetIssuerUri, audience: form.GetAudienceUri, notBefore: form.StartDate, expires: form.EndDate, signingCredentials: signingcredentials, claims: myclaims);
                JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                MyResult.TokenString = handler.WriteToken(token);
            }

            return View();
        }


    }
}