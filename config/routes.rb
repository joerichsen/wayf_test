Rails.application.routes.draw do
  root 'welcome#index'

  get '/saml/init' => 'saml#init'
  get '/saml/consume' => 'saml#consume'
end
