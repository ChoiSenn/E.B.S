// 외부 모듈
var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var bodyParser = require('body-parser');

// 서버 생성
var app = express();
// 서버 환셩 설정
app.settings.env = 'production';

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs'); // ejs 사용
app.engine('html', require('ejs').renderFile);

// 미들웨어 설정
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '/')));
app.use(bodyParser.urlencoded({extended: false}));

//app.use('/', indexRouter);
//app.use('/users', usersRouter);

// 라우팅

// 홈페이지
app.get('/', function(req, res, next){
  res.redirect('/home');
});

app.get('/home', function(req, res, next){
  res.render('home.ejs');
});

// 공지사항
app.get('/notice', function(req, res, next){
  res.render('notice.ejs');
});

// Q&A
app.get('/Q&A', function(req, res, next){
  res.render('Q&A.ejs');
});

// 입찰 공고
app.get('/posting', function(req, res, next){
  res.render('posting.ejs');
});

// 개찰 결과
app.get('/bidOpen', function(req, res, next){
  res.render('bidOpen.ejs');
});

// 로그인
app.get('/login', function(req, res, next){
  res.render('login.ejs');
});

// 회원가입
app.get('/signUp', function(req, res, next){
  res.render('signUp.ejs');
});

// 마이페이지
app.get('/mypage', function(req, res, next){
  res.render('mypage.ejs');
});

//로그인 요청
app.get('/plzlogin', function(req, res, next){
  res.render('plzlogin.ejs');
});



// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error',{
    message: err.message,
    error: {}
  });
});



var http = require('http').Server(app);

// 서버 동작
http.listen(80, function(){
  console.log('server Running!! >> http://localhost:80');
});

module.exports = app;
