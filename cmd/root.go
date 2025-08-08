package cmd

import (
	"fmt"
	"strings"
	"tinyauth/internal/auth"
	"tinyauth/internal/constants"
	"tinyauth/internal/docker"
	"tinyauth/internal/handlers"
	"tinyauth/internal/hooks"
	"tinyauth/internal/linkdb"
	"tinyauth/internal/providers"
	"tinyauth/internal/server"
	"tinyauth/internal/types"
	"tinyauth/internal/utils"

	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:   "tinyauth",
	Short: "The simplest way to protect your apps with a login screen.",
	Long:  `Tinyauth is a simple authentication middleware that adds OAuth with Google, Github and any generic OAuth provider to all of your docker apps.`,
	Run: func(cmd *cobra.Command, args []string) {
		var config types.Config
		err := viper.Unmarshal(&config)
		HandleError(err, "Failed to parse config")

		// Check if secrets have a file associated with them
		config.Secret = utils.GetSecret(config.Secret, config.SecretFile)
		config.GithubClientSecret = utils.GetSecret(config.GithubClientSecret, config.GithubClientSecretFile)
		config.GoogleClientSecret = utils.GetSecret(config.GoogleClientSecret, config.GoogleClientSecretFile)
		config.GenericClientSecret = utils.GetSecret(config.GenericClientSecret, config.GenericClientSecretFile)

		validator := validator.New()
		err = validator.Struct(config)
		HandleError(err, "Failed to validate config")

		log.Logger = log.Level(zerolog.Level(config.LogLevel))
		log.Info().Str("version", strings.TrimSpace(constants.Version)).Msg("Starting tinyauth")

		log.Debug().Msg("Getting domain")
		domain, err := utils.GetUpperDomain(config.AppURL)
		HandleError(err, "Failed to get upper domain")
		log.Info().Str("domain", domain).Msg("Using domain for cookie store")

		cookieId := utils.GenerateIdentifier(strings.Split(domain, ".")[0])
		sessionCookieName := fmt.Sprintf("%s-%s", constants.SessionCookieName, cookieId)
		csrfCookieName := fmt.Sprintf("%s-%s", constants.CsrfCookieName, cookieId)
		redirectCookieName := fmt.Sprintf("%s-%s", constants.RedirectCookieName, cookieId)

		log.Debug().Msg("Deriving HMAC and encryption secrets")

		hmacSecret, err := utils.DeriveKey(config.Secret, "hmac")
		HandleError(err, "Failed to derive HMAC secret")

		encryptionSecret, err := utils.DeriveKey(config.Secret, "encryption")
		HandleError(err, "Failed to derive encryption secret")

		// Split the config into service-specific sub-configs
		oauthConfig := types.OAuthConfig{
			GithubClientId:      config.GithubClientId,
			GithubClientSecret:  config.GithubClientSecret,
			GoogleClientId:      config.GoogleClientId,
			GoogleClientSecret:  config.GoogleClientSecret,
			GenericClientId:     config.GenericClientId,
			GenericClientSecret: config.GenericClientSecret,
			GenericScopes:       strings.Split(config.GenericScopes, ","),
			GenericAuthURL:      config.GenericAuthURL,
			GenericTokenURL:     config.GenericTokenURL,
			GenericUserURL:      config.GenericUserURL,
			GenericSkipSSL:      config.GenericSkipSSL,
			AppURL:              config.AppURL,
		}

		handlersConfig := types.HandlersConfig{
			AppURL:             config.AppURL,
			DisableContinue:    config.DisableContinue,
			Title:              config.Title,
			GenericName:        config.GenericName,
			CookieSecure:       config.CookieSecure,
			Domain:             domain,
			BackgroundImage:    config.BackgroundImage,
			OAuthAutoRedirect:  config.OAuthAutoRedirect,
			CsrfCookieName:     csrfCookieName,
			RedirectCookieName: redirectCookieName,
		}

		serverConfig := types.ServerConfig{
			Port:    config.Port,
			Address: config.Address,
		}

		authConfig := types.AuthConfig{
			CookieSecure:      config.CookieSecure,
			SessionExpiry:     config.SessionExpiry,
			Domain:            domain,
			SessionCookieName: sessionCookieName,
			HMACSecret:        hmacSecret,
			EncryptionSecret:  encryptionSecret,
		}

		hooksConfig := types.HooksConfig{
			Domain: domain,
		}

		if !utils.OAuthConfigured(config) {
			HandleError(fmt.Errorf("err no oauth"), "Unable to find a configured OAuth provider")
		}

		// Setup the services
		docker, err := docker.NewDocker()
		HandleError(err, "Failed to initialize docker")
		auth := auth.NewAuth(authConfig)
		providers := providers.NewProviders(oauthConfig)
		hooks := hooks.NewHooks(hooksConfig, auth, providers)
		linkDB := linkdb.New(config.LinkDBPath)
		adminEmails := strings.Split(config.AdminEmails, ",")
		handlers := handlers.NewHandlers(handlersConfig, auth, hooks, providers, docker, linkDB, adminEmails)
		srv, err := server.NewServer(serverConfig, handlers)
		HandleError(err, "Failed to create server")

		// Start up
		err = srv.Start()
		HandleError(err, "Failed to start server")
	},
}

func Execute() {
	err := rootCmd.Execute()
	HandleError(err, "Failed to execute root command")
}

func HandleError(err error, msg string) {
	if err != nil {
		log.Fatal().Err(err).Msg(msg)
	}
}

func init() {
	viper.AutomaticEnv()

	rootCmd.Flags().Int("port", 3000, "Port to run the server on.")
	rootCmd.Flags().String("address", "0.0.0.0", "Address to bind the server to.")
	rootCmd.Flags().String("secret", "", "Secret to use for the cookie.")
	rootCmd.Flags().String("secret-file", "", "Path to a file containing the secret.")
	rootCmd.Flags().String("app-url", "", "The tinyauth URL.")
	rootCmd.Flags().Bool("cookie-secure", false, "Send cookie over secure connection only.")
	rootCmd.Flags().String("github-client-id", "", "Github OAuth client ID.")
	rootCmd.Flags().String("github-client-secret", "", "Github OAuth client secret.")
	rootCmd.Flags().String("github-client-secret-file", "", "Github OAuth client secret file.")
	rootCmd.Flags().String("google-client-id", "", "Google OAuth client ID.")
	rootCmd.Flags().String("google-client-secret", "", "Google OAuth client secret.")
	rootCmd.Flags().String("google-client-secret-file", "", "Google OAuth client secret file.")
	rootCmd.Flags().String("generic-client-id", "", "Generic OAuth client ID.")
	rootCmd.Flags().String("generic-client-secret", "", "Generic OAuth client secret.")
	rootCmd.Flags().String("generic-client-secret-file", "", "Generic OAuth client secret file.")
	rootCmd.Flags().String("generic-scopes", "", "Generic OAuth scopes.")
	rootCmd.Flags().String("generic-auth-url", "", "Generic OAuth auth URL.")
	rootCmd.Flags().String("generic-token-url", "", "Generic OAuth token URL.")
	rootCmd.Flags().String("generic-user-url", "", "Generic OAuth user info URL.")
	rootCmd.Flags().String("generic-name", "Generic", "Generic OAuth provider name.")
	rootCmd.Flags().Bool("generic-skip-ssl", false, "Skip SSL verification for the generic OAuth provider.")
	rootCmd.Flags().Bool("disable-continue", false, "Disable continue screen and redirect to app directly.")
	rootCmd.Flags().String("oauth-auto-redirect", "none", "Auto redirect to the specified OAuth provider if configured. (available providers: github, google, generic)")
	rootCmd.Flags().Int("session-expiry", 86400, "Session (cookie) expiration time in seconds.")
	rootCmd.Flags().Int("log-level", 1, "Log level.")
	rootCmd.Flags().String("app-title", "Tinyauth", "Title of the app.")
	rootCmd.Flags().String("background-image", "/background.jpg", "Background image URL for the login page.")
	rootCmd.Flags().String("link-db-path", "data", "Directory for account links.")
	rootCmd.Flags().String("admin-emails", "", "Comma separated list of admin emails.")

	viper.BindEnv("port", "PORT")
	viper.BindEnv("address", "ADDRESS")
	viper.BindEnv("secret", "SECRET")
	viper.BindEnv("secret-file", "SECRET_FILE")
	viper.BindEnv("app-url", "APP_URL")
	viper.BindEnv("cookie-secure", "COOKIE_SECURE")
	viper.BindEnv("github-client-id", "GITHUB_CLIENT_ID")
	viper.BindEnv("github-client-secret", "GITHUB_CLIENT_SECRET")
	viper.BindEnv("github-client-secret-file", "GITHUB_CLIENT_SECRET_FILE")
	viper.BindEnv("google-client-id", "GOOGLE_CLIENT_ID")
	viper.BindEnv("google-client-secret", "GOOGLE_CLIENT_SECRET")
	viper.BindEnv("google-client-secret-file", "GOOGLE_CLIENT_SECRET_FILE")
	viper.BindEnv("generic-client-id", "GENERIC_CLIENT_ID")
	viper.BindEnv("generic-client-secret", "GENERIC_CLIENT_SECRET")
	viper.BindEnv("generic-client-secret-file", "GENERIC_CLIENT_SECRET_FILE")
	viper.BindEnv("generic-scopes", "GENERIC_SCOPES")
	viper.BindEnv("generic-auth-url", "GENERIC_AUTH_URL")
	viper.BindEnv("generic-token-url", "GENERIC_TOKEN_URL")
	viper.BindEnv("generic-user-url", "GENERIC_USER_URL")
	viper.BindEnv("generic-name", "GENERIC_NAME")
	viper.BindEnv("generic-skip-ssl", "GENERIC_SKIP_SSL")
	viper.BindEnv("disable-continue", "DISABLE_CONTINUE")
	viper.BindEnv("oauth-auto-redirect", "OAUTH_AUTO_REDIRECT")
	viper.BindEnv("session-expiry", "SESSION_EXPIRY")
	viper.BindEnv("log-level", "LOG_LEVEL")
	viper.BindEnv("app-title", "APP_TITLE")
	viper.BindEnv("background-image", "BACKGROUND_IMAGE")
	viper.BindEnv("link-db-path", "LINK_DB_PATH")
	viper.BindEnv("admin-emails", "ADMIN_EMAILS")

	viper.BindPFlags(rootCmd.Flags())
}
