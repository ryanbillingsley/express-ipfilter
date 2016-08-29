module.exports = function(grunt){
  'use strict';

  require('load-grunt-tasks')(grunt);
  grunt.initConfig({
    watch: {
      scripts: {
        files: ['src/**/*.js', 'test/**/*.js'],
        tasks: ['test'],
        options: {
          spawn: false
        }
      }
    },
    copy: {
      ci: {
        files: [
          { expand: true, src: 'test-results.xml', dest: process.env.CIRCLE_TEST_REPORTS+'/mocha/' }
        ]
      }
    },
    eslint: {
      all: ['Gruntfile.js', 'src/**/*.js', 'test/**/*.js'],
      options: {
        'ecmaVersion': 6
      }
    },
    'babel': {
      options: {
        sourceMap: true
      },
      dist: {
        files: {
          'lib/ipfilter.js': 'src/ipfilter.js',
          'lib/deniedError.js': 'src/deniedError.js'
        }
      }
    },
    mochaTest: {
      ci: {
        src: 'test/**/*.js',
        options: {
          reporter: 'mocha-junit-reporter',
          captureFile: 'junit/test-results.xml'
        }
      }
    },
    mocha_istanbul: {
      coverage: {
        src: 'test',
        options: {
          mask: '*.spec.js'
        }
      },
      ci: {
        src: 'test',
        options: {
          mask: '*.spec.js',
        }
      }
    },
    checkDependencies: {
      this: {}
    },
  });

  grunt.registerTask('default', ['checkDependencies','eslint','babel:dist']);
  grunt.registerTask('test', ['checkDependencies','eslint','babel','mocha_istanbul']);
  grunt.registerTask('ci', ['checkDependencies','eslint','babel','mochaTest:ci','mocha_istanbul:ci','copy:ci']);
};
