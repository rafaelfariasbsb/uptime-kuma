<template>
    <div class="my-4">
        <div v-if="!settingsLoaded" class="text-center py-4">
            <div class="spinner-border spinner-border-sm" role="status" />
        </div>

        <template v-else>
            <p class="text-muted">
                {{ $t("Configure Microsoft Entra ID (Azure AD) to allow users to sign in with their Microsoft accounts.") }}
            </p>

            <h5 class="my-4 settings-subheading">{{ $t("Microsoft SSO") }}</h5>

            <div class="mb-3 form-check form-switch">
                <input
                    id="sso-enabled"
                    v-model="form.enabled"
                    class="form-check-input"
                    type="checkbox"
                />
                <label class="form-check-label" for="sso-enabled">
                    {{ $t("Enable Microsoft SSO") }}
                </label>
            </div>

            <template v-if="form.enabled">
                <div class="mb-3">
                    <label for="sso-client-id" class="form-label">
                        {{ $t("Application (Client) ID") }} <span class="text-danger">*</span>
                    </label>
                    <input
                        id="sso-client-id"
                        v-model="form.clientId"
                        type="text"
                        class="form-control"
                        placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                        autocomplete="off"
                        required
                    />
                    <div class="form-text">
                        {{ $t("Found in Azure Portal → App registrations → your app → Overview.") }}
                    </div>
                </div>

                <div class="mb-3">
                    <label for="sso-tenant-id" class="form-label">
                        {{ $t("Directory (Tenant) ID") }}
                    </label>
                    <input
                        id="sso-tenant-id"
                        v-model="form.tenantId"
                        type="text"
                        class="form-control"
                        placeholder="common"
                        autocomplete="off"
                    />
                    <div class="form-text">
                        {{ $t('Use "common" for multi-tenant or personal accounts. Use your tenant ID to restrict to your organization.') }}
                    </div>
                </div>

                <div class="mb-3">
                    <label for="sso-client-secret" class="form-label">
                        {{ $t("Client Secret") }} <span v-if="!hasClientSecret" class="text-danger">*</span>
                    </label>
                    <input
                        id="sso-client-secret"
                        v-model="form.clientSecret"
                        type="password"
                        class="form-control"
                        :placeholder="hasClientSecret ? $t('Leave blank to keep current secret') : ''"
                        autocomplete="new-password"
                    />
                    <div class="form-text">
                        {{ $t("Found in Azure Portal → App registrations → your app → Certificates & secrets.") }}
                    </div>
                </div>

                <div class="mb-3">
                    <label class="form-label">{{ $t("Allowed Email Domains") }}</label>
                    <div class="d-flex gap-2 mb-2">
                        <input
                            v-model="newDomain"
                            type="text"
                            class="form-control"
                            placeholder="df.senac.br"
                            @keydown.enter.prevent="addDomain"
                        />
                        <button type="button" class="btn btn-outline-secondary" @click="addDomain">
                            {{ $t("Add") }}
                        </button>
                    </div>
                    <div v-if="form.allowedDomains.length === 0" class="form-text text-warning">
                        {{ $t("No domains configured — all Microsoft accounts from this tenant can log in (if they have a local account).") }}
                    </div>
                    <div v-else class="d-flex flex-wrap gap-2">
                        <span
                            v-for="(domain, idx) in form.allowedDomains"
                            :key="idx"
                            class="badge bg-secondary d-flex align-items-center gap-1"
                            style="font-size: 0.85rem;"
                        >
                            @{{ domain }}
                            <button
                                type="button"
                                class="btn-close btn-close-white"
                                style="font-size: 0.6rem;"
                                @click="removeDomain(idx)"
                            />
                        </span>
                    </div>
                    <div class="form-text">
                        {{ $t("Only users with email addresses from these domains will be allowed to sign in.") }}
                    </div>
                </div>

                <div class="mb-4 p-3 border rounded bg-light">
                    <strong>{{ $t("Redirect URI to configure in Azure") }}:</strong>
                    <code class="ms-2 user-select-all">{{ redirectUri }}</code>
                </div>
            </template>

            <button
                class="btn btn-primary"
                :disabled="saving"
                @click="save"
            >
                <span v-if="saving" class="spinner-border spinner-border-sm me-1" role="status" />
                {{ $t("Save") }}
            </button>
        </template>
    </div>
</template>

<script>
export default {
    data() {
        return {
            settingsLoaded: false,
            saving: false,
            hasClientSecret: false,
            newDomain: "",
            form: {
                enabled: false,
                clientId: "",
                tenantId: "common",
                clientSecret: "",
                allowedDomains: [],
            },
        };
    },

    computed: {
        redirectUri() {
            return window.location.origin + "/auth/microsoft/callback";
        },
    },

    mounted() {
        this.load();
    },

    methods: {
        load() {
            this.$root.getSocket().emit("getMicrosoftSSOSettings", (res) => {
                if (res.ok) {
                    this.form.enabled = res.data.enabled;
                    this.form.clientId = res.data.clientId;
                    this.form.tenantId = res.data.tenantId || "common";
                    this.form.clientSecret = "";
                    this.form.allowedDomains = res.data.allowedDomains || [];
                    this.hasClientSecret = res.data.hasClientSecret;
                }
                this.settingsLoaded = true;
            });
        },

        addDomain() {
            const domain = this.newDomain.trim().toLowerCase().replace(/^@/, "");
            if (domain && !this.form.allowedDomains.includes(domain)) {
                this.form.allowedDomains.push(domain);
            }
            this.newDomain = "";
        },

        removeDomain(idx) {
            this.form.allowedDomains.splice(idx, 1);
        },

        save() {
            if (this.form.enabled && !this.form.clientId) {
                this.$root.toastError("Application (Client) ID is required.");
                return;
            }
            if (this.form.enabled && !this.hasClientSecret && !this.form.clientSecret) {
                this.$root.toastError("Client Secret is required.");
                return;
            }

            this.saving = true;
            this.$root.getSocket().emit("setMicrosoftSSOSettings", this.form, (res) => {
                this.saving = false;
                this.$root.toastRes(res);
                if (res.ok) {
                    this.load();
                }
            });
        },
    },
};
</script>
