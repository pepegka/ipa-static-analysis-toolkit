import SwiftUI

struct LoginView: View {
    @EnvironmentObject var appStore: AppStoreStore
    @Environment(\.dismiss) private var dismiss

    @State private var email = ""
    @State private var password = ""
    @State private var code = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                Image(systemName: "person.badge.key.fill")
                    .font(.title2).foregroundStyle(.tint)
                VStack(alignment: .leading, spacing: 1) {
                    Text("Sign in to the App Store").font(.headline)
                    Text("Your password is sent only to Apple via the bundled ipatool helper and is never stored by this app.")
                        .font(.caption2).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            if appStore.awaitingTwoFactor {
                Text("Enter the 2-factor code sent to your trusted device.")
                    .font(.callout)
                TextField("2FA code", text: $code)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { submit() }
            } else {
                TextField("Apple ID email", text: $email)
                    .textFieldStyle(.roundedBorder)
                    .textContentType(.username)
                SecureField("Password", text: $password)
                    .textFieldStyle(.roundedBorder)
                    .textContentType(.password)
                    .onSubmit { submit() }
            }

            if let err = appStore.loginError {
                Text(err).font(.caption).foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                if appStore.isAuthenticating { ProgressView().controlSize(.small) }
                Spacer()
                Button("Cancel") {
                    appStore.cancelLogin()
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
                Button(appStore.awaitingTwoFactor ? "Verify" : "Sign In") { submit() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(appStore.isAuthenticating || !canSubmit)
            }
        }
        .padding(20)
        .frame(width: 420)
        .onChange(of: appStore.isLoggedIn) { _, loggedIn in
            if loggedIn { dismiss() }
        }
    }

    private var canSubmit: Bool {
        if appStore.awaitingTwoFactor { return !code.trimmingCharacters(in: .whitespaces).isEmpty }
        return !email.trimmingCharacters(in: .whitespaces).isEmpty && !password.isEmpty
    }

    private func submit() {
        guard canSubmit else { return }
        Task {
            if appStore.awaitingTwoFactor {
                await appStore.submitTwoFactor(code: code.trimmingCharacters(in: .whitespaces))
            } else {
                await appStore.login(email: email.trimmingCharacters(in: .whitespaces), password: password)
            }
        }
    }
}
