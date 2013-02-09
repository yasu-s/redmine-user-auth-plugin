import org.acegisecurity.providers.ProviderManager
import org.acegisecurity.providers.anonymous.AnonymousAuthenticationProvider
import org.acegisecurity.providers.rememberme.RememberMeAuthenticationProvider
import hudson.model.Hudson

authenticationManager(ProviderManager) {
    providers = [
        redmineAuth,

    // these providers apply everywhere
        bean(RememberMeAuthenticationProvider) {
            key = Hudson.getInstance().getSecretKey();
        },
        // this doesn't mean we allow anonymous access.
        // we just authenticate anonymous users as such,
        // so that later authorization can reject them if so configured
        bean(AnonymousAuthenticationProvider) {
            key = "anonymous"
        }
    ]
}