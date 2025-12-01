job "darkmode" {
  type = "service"

  group "darkmode" {
    network {
      port "http" { }
    }

    service {
      name     = "darkmode"
      port     = "http"
      provider = "nomad"
      tags = [
        "traefik.enable=true",
        "traefik.http.routers.darkmode.rule=Host(`darkmode.datasektionen.se`)",
        "traefik.http.routers.darkmode.tls.certresolver=default",
      ]
    }

    task "darkmode" {
      driver = "docker"

      config {
        image = var.image_tag
        ports = ["http"]
      }

      template {
        data        = <<ENV
{{ with nomadVar "nomad/jobs/darkmode" }}
OIDC_CLIENT_SECRET={{ .oidc_clinet_secret }}
DATABASE_URL=postgresql://darkmode:{{ .database_password }}@postgres.dsekt.internal:5432/darkmode
{{ end }}
PORT={{ env "NOMAD_PORT_http" }}
OIDC_PROVIDOR=https://sso.datasektionen.se/op
OIDC_CLIENT_ID=darkmode
OIDC_REDIRECT_URL=https://darkmode.datasektionen.se/oidc/callback
WEBHOOKS=http://taitan.nomad.dsekt.internal/
ENV
        destination = "local/.env"
        env         = true
      }

      resources {
        memory = 15
      }
    }
  }
}

variable "image_tag" {
  type = string
  default = "ghcr.io/datasektionen/darkmode:latest"
}
