from flask import Flask, request, redirect, session, render_template
from onelogin.saml2.auth import OneLogin_Saml2_Auth
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)
"""
BU FONKSİYONUN AMACI TAMAMEN FLASKTAN GELEN REQ(İSTEKLERİ) AUTH FONKSİYONUNUN YAPISINA UYGUN ŞEKİLDE ONA VERMEKTİR
Çünkü OneLogin_Saml2_Auth sınıfı framework bağımsızdır ve bu bilgileri manuel ister.
"""
def prepare_flask_request():
    return {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.host,
        'server_port': request.environ.get('SERVER_PORT'),
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy()
    }
"""
ASIL OLAY BURDADIR GELEN REQUESTLERİ İNCELER VE ONA GÖRE HAREKET EDER ,AYRICA SETTİNG JSON İÇİNDEKİ YAZILANLARI OKUR!!!
"""
def init_saml_auth(req):
    return OneLogin_Saml2_Auth(req, custom_base_path="saml")
"""
BURASININ YAPTIĞI İŞ EĞER SAML DA GİRİŞ ZATEN YAPILDIYSA BİZİ DİREKT HOME.HTML YE ATAR
"""
@app.route('/')
def index():
    if 'samlUserdata' in session:
        return render_template('home.html', attributes=session['samlUserdata'])
    return render_template('login.html')


@app.route('/saml/login')
def saml_login():
    req = prepare_flask_request()
    auth = init_saml_auth(req)
    return redirect(auth.login())

@app.route('/saml/acs', methods=['POST'])
def saml_acs():
    req = prepare_flask_request()
    auth = init_saml_auth(req)
    auth.process_response()
    errors = auth.get_errors()

    print("SAML Errors:", errors)
    print("Last Error Reason:", auth.get_last_error_reason())

    if 'There is no AttributeStatement on the Response' in auth.get_last_error_reason():
        session['samlUserdata'] = {'Kullanici': ['Anonim']}
        return redirect('/')

    if not errors:
        attributes = auth.get_attributes()
        if attributes:
            session['samlUserdata'] = attributes
        else:
            session['samlUserdata'] = {'Kullanici': ['Anonim']}
        return redirect('/')
    else:
        return f"<h3>Hata: {errors}</h3><br><strong>Detay:</strong> {auth.get_last_error_reason()}"

@app.route('/saml/logout')
def saml_logout():
    session.clear()
    return redirect('/')

@app.route('/metadata/')
def metadata():
    req = prepare_flask_request()
    auth = init_saml_auth(req)
    settings = auth.get_settings()
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)

    if not errors:
        return metadata, 200, {'Content-Type': 'text/xml'}
    else:
        return f"Metadata Error: {errors}", 500

if __name__ == '__main__':
    app.run(debug=True)
