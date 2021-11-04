module GoogleSignIn::ButtonHelper
  def google_sign_in_button(text = nil, proceed_to:, **options, &block)
    form_with url: ENV['GOOGLE_SIGN_IN_MAIN_DOMAIN'] + google_sign_in.authorization_path, local: true do
      hidden_field_tag(:proceed_to, proceed_to, id: nil) + button_tag(text, name: nil, **options, &block)
    end
  end
end
