
from flask import Flask, jsonify, render_template

from backend.routes.prediction import prediction_bp
from backend.routes.history import history_bp


def create_app():

    app = Flask(
        __name__,
        template_folder="../web/templates",
        static_folder="../web/static",
        static_url_path="/static"
    )

    app.register_blueprint(prediction_bp)
    app.register_blueprint(history_bp)

    @app.route("/")
    def home():
        return jsonify({
            "status": "running",
            "application": "AI-Based Phishing URL Detection System",
            "version": "1.0.0",
            "mode": "OFFLINE_FIRST",
            "endpoints": {
                "dashboard": "/dashboard",
                "health": "/api/health",
                "prediction": "/api/predict",
                "offline_analysis": "/api/analyze",
                "history": "/api/history"
            }
        }), 200

    @app.route("/dashboard")
    def dashboard():
        return render_template("index.html")

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            "success": False,
            "error": "Resource not found."
        }), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        return jsonify({
            "success": False,
            "error": "Method not allowed."
        }), 405

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )